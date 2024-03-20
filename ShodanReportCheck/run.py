"""
Performs security assessments of domains using Shodan API.

This class is designed to analyze domain security by resolving domain
names to IP addresses, fetching Shodan reports, and assessing these
reports for known vulnerabilities. It processes and inserts detailed
results into a database, including information about vulnerabilities
and their severity.

Note:
    The environment variable `SHODAN_API_KEY` must be set with a valid API key to fetch reports from URL
     <https://api.shodan.io/shodan/>.
"""

# Hint: see reference, e.g.:
# - <https://developer.shodan.io/>
# - <https://developer.shodan.io/api>


import logging
import os
import time
from collections import defaultdict
import requests
from azure.functions import HttpRequest, HttpResponse
from SharedCode.activityinfo import ActivityInfoData
from SharedCode.abstract_template import AbstractTemplateCheck, CheckResult, lookup_ip_addresses
from SharedCode.helpers import generate_unique_identifier, is_invalid_param_string
from SharedCode.common import parse_request, initialize_activity_info, handle_exception

ENV_VAR_API_KEY = "SHODAN_API_KEY"

API_REPORT_URL_TEMPLATE = "https://api.shodan.io/shodan/host/{ip_address}?key={api_key}"
MANUAL_REPORT_URL_TEMPLATE = "https://www.shodan.io/host/{ip_address}"
API_CALL_PAUSE = 1  # limit API request rate to no more than 1 per second (as read on Internet)


class ShodanReportCheck(AbstractTemplateCheck):
    """
    A class for performing security checks on domains via Shodan API.

    It resolves domain names to IP addresses, fetches Shodan reports, and analyzes
    them for known vulnerabilities. Results are processed and inserted into a database
    with detailed information about each check performed.

    Attributes:
        activityinfo_data (ActivityInfoData): An object containing
        data related to activities, resource IDs, and schemas.
        resource_ids (dict): Identifiers for database resources.
        schemas (dict): Definitions of database schemas.
        checks_lookup (dict): Lookup information for checks performed.

    Methods:
        check_domain: Resolves domain name, fetches and analyzes Shodan report.
        evaluate_report_and_insert_ip: Processes Shodan report and inserts IP data
            into the database.
        get_test_results: Extracts vulnerability data from Shodan report.
        insert_ip_into_db: Inserts or retrieves a record ID for an IP address in
            the database.
    """

    def __init__(
            self,
            activityinfo_data: ActivityInfoData,
            **kwargs
    ):
        super().__init__(
            check_name="Known vulnerabilities",
            activityinfo_data=activityinfo_data,
            **kwargs
        )

        self.api_key = kwargs.get("api_key", os.environ.get(ENV_VAR_API_KEY))
        if is_invalid_param_string(self.api_key):
            raise ValueError(
                f"API key is undefined or empty "
                f"(check environment variable '{ENV_VAR_API_KEY}')!"
            )

    def check_domain(self, domain_name: str, **kwargs) -> (CheckResult, dict):
        record_id = kwargs.get("record_id")
        if not record_id:
            return CheckResult.ERROR, {"data": "Record ID is missing!"}

        ip_addresses = lookup_ip_addresses(domain_name)
        if not ip_addresses:
            return CheckResult.ERROR, {"data": "No IP addresses found!"}

        worst_result = CheckResult.ERROR
        ip_details = []

        for ip_address in ip_addresses:
            shodan_report = self.fetch_shodan_report(ip_address)
            if not shodan_report:
                continue

            check_grade, ip_id = self.evaluate_report_and_insert_ip(
                shodan_report, record_id, ip_address
            )

            # Compare the current severity level grade and keep the worst/highest severity one
            if (check_grade == CheckResult.UNKNOWN or
                    (worst_result != CheckResult.UNKNOWN and
                     check_grade.__dict__['_sort_order_'] > worst_result.__dict__['_sort_order_'])):
                worst_result = check_grade

            ip_details.append({
                "ip_address": ip_address,
                "check_grade": check_grade.value,
                "ip_id": ip_id
            })

        test_data_msg = f"Worst Grade: '{worst_result.value}'\n"
        for detail in ip_details:
            test_data_msg += (
                f"IP address '{detail['ip_address']}': Grade '{detail['check_grade']}'"
                f" - <https://www.shodan.io/host/{detail['ip_address']}>\n")

        return worst_result, {
            'data': test_data_msg,
            'ip_details': ip_details
        }

    def evaluate_report_and_insert_ip(self, report: dict, record_id: str, ip_address: str) -> (CheckResult, str):
        """
        Evaluates a Shodan report for a given IP address and inserts the evaluation result into the database.

        This method processes a Shodan report to extract unique vulnerabilities, determines the highest score 
        (severity level) among those vulnerabilities, and then updates the database with this information. 
        It returns the determined check grade and the database record ID for the IP address.

        Args:
            report (dict): The Shodan report containing vulnerability data for a specific IP address.
            record_id (str): The record ID associated with the domain check in the database.
            ip_address (str): The IP address being evaluated.

        Returns:
            tuple: A tuple containing two elements:
                - CheckResult: An enumeration value representing the severity level of the vulnerabilities found.
                - str: The database record ID for the inserted or updated IP address.
        """
        unique_vulnerabilities = define_all_unique_vulnerabilities(report)
        check_grade = define_highest_score(unique_vulnerabilities)
        ip_id = self.insert_ip_into_db(record_id, ip_address, str(check_grade.value))
        return check_grade, ip_id

    def insert_ip_into_db(self, record_id: str, ip_address: str, grade: str) -> str:
        ip_rows = self.activityinfo_data.fetch_ip_row(record_id, ip_address)
        if int(ip_rows.get('rows') == 0):
            fields = {
                self.schemas[self.resource_ids['IP addresses']]['IP']: str(ip_address),
                self.schemas[self.resource_ids['IP addresses']]['Grade']: grade
            }

            ip_record_id = generate_unique_identifier()
            self.activityinfo_data.update_record(
                record_id=ip_record_id,
                fields=fields,
                form_id=self.activityinfo_data.resource_ids.get('IP addresses'),
                parent_id=record_id
            )
            return ip_record_id
        else:
            existing_ip_record_id = ip_rows['columns']['$$id']['values'][0]
            self.activityinfo_data.update_record(
                record_id=existing_ip_record_id,
                fields={'Grade': grade},  # Update only the grade field
                form_id=self.activityinfo_data.resource_ids.get('IP addresses'),
                parent_id=record_id
            )
            return existing_ip_record_id

    def fetch_shodan_report(self, ip_address: str, api_call_pause: float = API_CALL_PAUSE) -> Optional[dict]:
        """
        Fetches the security report for a given IP address from the Shodan API.

        The method retrieves a detailed report containing security-related information
        about the specified IP address by making a request to the Shodan API. If the
        request fails or an error occurs, None is returned.

        Args:
            ip_address (str): The IP address for which to retrieve the Shodan report.
            api_call_pause (float): A pause in seconds to wait after calling the API, to limit the API request rate

        Returns:
            Optional[dict]: A dictionary containing the Shodan report if the request
            is successful, None otherwise.
        """
        url = API_REPORT_URL_TEMPLATE.format(ip_address=ip_address, api_key=self.api_key)
        try:
            response = requests.get(url, timeout=10)
            time.sleep(api_call_pause)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logging.exception(f"An error occurred while fetching report for IP address '{ip_address}': {e}")
            return None  # Return None or an empty dict if an error occurs


# Specific static utility functions:

def define_all_unique_vulnerabilities(report: dict) -> dict:
    """
    Aggregates all unique vulnerabilities found in a Shodan report.

    Args:
        report (dict): A Shodan report containing vulnerability data.

    Returns:
        dict: A dictionary with aggregated vulnerability details.
    """
    vulnerabilities = defaultdict(dict)
    for port_info in report.get('data', []):
        port_vulns = port_info.get('vulns', {})
        for vuln, details in port_vulns.items():
            vulnerabilities[vuln].update(details)
    return vulnerabilities


def count_vulnerabilities(report: dict) -> int:
    """Counts the number of vulnerabilities in the given report."""
    return len(report.get('vulns', []))


def define_highest_score(vulnerabilities: dict) -> CheckResult:
    """Determines the severity level based on the highest CVSS score in the given vulnerabilities dictionary."""
    if not isinstance(vulnerabilities, dict):
        return CheckResult.UNKNOWN
    if len(vulnerabilities) <= 0:
        return CheckResult.NO_RESULT
    try:
        scores = [round(float(details.get('cvss') or 0)) for details in vulnerabilities.values()]
        highest_score = max(scores)
        if highest_score < 4:
            return CheckResult.LOW
        elif 4 <= highest_score < 7:
            return CheckResult.MEDIUM
        elif 7 <= highest_score < 9:
            return CheckResult.HIGH
        else:
            return CheckResult.CRITICAL
    except (TypeError, ValueError) as e:
        logging.exception("Exception while parsing value 'cvss': %s", str(e))

        return CheckResult.UNKNOWN

def main(req: HttpRequest) -> HttpResponse:
    try:
        # Parse domain from the request
        domain_data = parse_request(req)
        
        # Initialize activity data and Shodan check
        activity_data = initialize_activity_info()
        check = ShodanReportCheck(activity_data)
        
        # Here, you would iterate over domains or handle a single domain
        # Depending on your implementation and request format
        results = [check.check_domain(domain) for domain in domain_data]

        return HttpResponse(body=str(results), status_code=200)
    except Exception as e:
        return handle_exception(e)