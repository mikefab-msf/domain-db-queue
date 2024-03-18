"""
MSF-OCB Domain DB Checks (2024-01a)
**IMPORTANT**
For Internal Use Only -- NO WARRANTY! -- Risk of DATA LOSS/CORRUPTION/DISCLOSURE!!
Please first carefully read the instructions in the file "README.md" provided with this project.

Abstract base class, to be subclassed by each specific check, containing the base common logic
shared between all checks, e.g. initialisation, verifications, data accesses, logging...
(using the template method design pattern, see e.g.
<https://en.wikipedia.org/wiki/Template_method_pattern>)

Each concrete child class should implement specific check actions to perform for a given domain name
by overriding the abstract method "check_domain()".

Then the implemented check actions may be sequentially executed on each domain name fetched from
the associated custom database for the "Domain DB" app by simply calling method
"check_all_domains()".

The result of each domain check is inserted back into the database with a result code
("OK", "NOK" or "ERROR"), and with extra info data for the executed check
(with error message(s) if any occurred).

Main specific dependencies:
- Python v3.12 or later
- custom ActivityInfo database access module
- standard Requests HTTP library
"""
import logging
import socket
import base64
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Callable, Optional, List, Tuple

from azure.storage.queue import QueueClient
import os
import json

import requests
import requests.structures

from SharedCode.activityinfo import ActivityInfoData
from SharedCode.helpers import is_invalid_param_string, generate_unique_identifier


# Fetch the connection string from an environment variable
storage_connection_string = os.getenv("AzureWebJobsStorage")
queue_name = "domain-checks-queue"

HTTP_REQUEST_TIMEOUT = 10  # Default timeout for HTTP requests (in seconds)


class CheckResult(Enum):
    """
    Enum class listing all possible check outcomes.
    ("OK" if check passed, "NOK" is check executed but failed, "ERROR" if check could not be executed
    typically because of network errors)

    *IMPORTANT*: the order of the items in the list below is significant, i.a. in specific sorting routines for ratings!
    """
    # Hint: see <https://docs.python.org/3/howto/enum.html#restricted-enum-subclassing>

    # - generic check results:
    OK = "OK"
    NOK = "NOK"
    ERROR = "ERROR"
    N_A = "N/A"
    UNKNOWN = "Unknown"
    ERROR_IGNORED = "-"
    NO_RESULT = "/"

    # - check results (ratings) used by specific check classes `SslLabsCheck` (all), 'SecurityHeadersCheck' (A-F):
    #   Note: the order of items below is significant: A+ > A > A- > B > ... > F > ... - do not reorder them!
    A_PLUS = "A+"
    A = "A"
    A_MINUS = "A-"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"
    M = "M"
    T = "T"

    # - check results (ratings) used by specific check class `ShodanReportCheck`:
    #   Note: the order of items below is significant: LOW < MEDIUM < HIGH < CRITICAL - do not reorder them!
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    # - check results (ratings/scores) used by specific check class `SshCheck`:
    #   Note: the order of items below is significant: UNKNOWN < INSECURE < WEAK < SECURE - do not reorder them!
    INSECURE = "Insecure"
    WEAK = "Weak"
    SECURE = "Secure"


class AbstractTemplateCheck(ABC):
    """
    Abstract base class, to be subclassed by each specific check, containing the base common logic
    shared between all checks e.g. initialisation, verifications, database accesses, logging...
    """

    def __init__(
            self,
            check_name: str,
            activityinfo_data: ActivityInfoData,
            **kwargs
    ):

        if is_invalid_param_string(check_name):
            raise ValueError("Test name should be provided!")
        self.check_name = check_name
        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("class '%s': check '%s': initializing...", self.__class__.__name__, self.check_name)

        if activityinfo_data is None or not isinstance(activityinfo_data, ActivityInfoData):
            raise ValueError("ActivityInfoData object should be provided!")
        self.activityinfo_data = activityinfo_data

        self.schemas = activityinfo_data.schemas
        self.resource_ids = activityinfo_data.resource_ids
        self.checks_lookup = activityinfo_data.checks_lookup
        self.check_field_id = ""

        # If the supplied ActivityInfo object is marked for test only (typically when unit tests), stop processing here
        if activityinfo_data.for_test_only:
            if logging.getLogger().isEnabledFor(logging.INFO):
                logging.info("class '%s': check '%s': stopping initialization"
                              " (ActivityInfoData object mode 'for_test_only' is %s)",
                              self.__class__.__name__, self.check_name, activityinfo_data.for_test_only)
            return

        domains_form_id = self.activityinfo_data.resource_ids.get('Domains')
        domains_form_field_ids = self.activityinfo_data.schemas.get(domains_form_id)

        for key in domains_form_field_ids:
            if key == check_name:
                self.check_field_id = domains_form_field_ids[key]
                break  # Exit the loop once the value is found

        if is_invalid_param_string(self.check_field_id):
            raise RuntimeError(f"Field ID not found in DB for check '{check_name}'!")

        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("class '%s': check '%s': initialized.", self.__class__.__name__, self.check_name)

    def update_results_to_db(self, domain_info: dict,
                             check_result: CheckResult, check_result_details: dict) -> None:
        """
            Updates the database with the latest check results for a domain.

            Args:
            domain_info (str): The domain identifier.
            check_result (Any): The outcome of the domain check.
            check_data (Any): Data associated with the check.
            record_id (int): Database record ID for the update.
            """
        # Prepare the fields for update or insertion
        fields = {
            self.schemas[self.resource_ids['Results']]['Data']:
            check_result_details['data'] if 'data' in check_result_details else "",
            self.schemas[self.resource_ids['Results']]['Result']:
            check_result.value if isinstance(check_result, CheckResult) else CheckResult.ERROR.value,
            self.schemas[self.resource_ids['Results']]['Last updated']:
            datetime.today().strftime("%Y-%m-%d"),
            self.schemas[self.resource_ids['Results']]['Checks']:
            self.checks_lookup[self.check_name],
        }

        if 'ip_id' in check_result_details:
            fields[self.schemas[self.resource_ids['Results']]['IP addresses']] = \
                self.resource_ids['IP addresses'] + ':' + check_result_details['ip_id']

        # Check if the record exists for this domain and check
        unique_key = f"{domain_info['name']}-{self.checks_lookup[self.check_name]}"

        result_record_id = self.activityinfo_data.check_domain_hash.get(unique_key)

        # If the record exists, update it. Otherwise, generate a new ID for insertion
        if not result_record_id:
            result_record_id = generate_unique_identifier()

        try:
            self.activityinfo_data.update_record(
                record_id=result_record_id,
                form_id=self.activityinfo_data.resource_ids.get('Results'),
                fields=fields,
                parent_id=domain_info['id']
            )
            if logging.getLogger().isEnabledFor(logging.INFO):
                logging.info(
                    "check \"%s\" for domain \"%s\": "
                    "successfully updated the check result in the database.",
                    self.check_name, domain_info['name'])
        except requests.RequestException as e:
            logging.exception(
                "check \"%s\" for domain \"%s\": "
                "failed to insert the check result due to request exception '%s'!",
                self.check_name, domain_info['name'], e)
        except Exception as e:
            logging.exception(
                "check \"%s\" for domain \"%s\": "
                "failed to insert the check result due to unexpected exception '%s'!",
                self.check_name, domain_info['name'], e)

    def get_domain_rows(
        self,
        specific_domains: Optional[List[str]] = None
    ) -> List[Tuple[str, ...]]:
        """
        Retrieves domain rows based on specific domains or all
        available domains from the class's activity data.

        Args:
            specific_domains (Optional[List[str]]): List of specific domain names to filter.
                If None, all domain rows from the activity data are used.

        Returns:
            List[Tuple[str, ...]]: Filtered list of domain rows.
        """
        if specific_domains is None:
            return self.activityinfo_data.domains_rows

        return [
            row for row in self.activityinfo_data.domains_rows if row[0] in specific_domains
        ]

    def check_all_domains(self, specific_domains: Optional[List[str]] = None) -> None:
        """
        Enqueues each domain to be checked asynchronously.
        If specific_domains is provided, only enqueue those domains;
        otherwise, enqueue all domains from the database.

        Args:
            specific_domains List[str]: A list of domain names.
                Defaults to None, which will enqueue all domains from the database.
        """
        domains_rows = self.get_domain_rows(specific_domains)

        # Reference to the queue client using the Azure storage connection string and the queue name
        queue_client = QueueClient.from_connection_string(storage_connection_string, queue_name)

        logging.info("- - - - - - - - Enqueuing check \"%s\" (%s) - - - - - - - -",
                     self.check_name, self.__class__.__name__)
        logging.info("Enqueuing check \"%s\" for %s domains...", self.check_name,
                     ("the selected" if specific_domains else "all"))

        for domain_row in domains_rows:
            domain_name, domain_owner, record_id = domain_row

            check_info = f"Enqueuing check \"{self.check_name}\" for domain \"{domain_name}\""
            logging.info("%s...", check_info)

            # Construct the message to be sent to the queue
            message = {
                'check_name': self.check_name,
                'domain_name': domain_name,
                'domain_owner': domain_owner,
                'record_id': record_id
            }
            encoded_message = base64.b64encode(json.dumps(message).encode('utf-8')).decode('utf-8')
            # Send the message to the queue
            queue_client.send_message(encoded_message)

            logging.info("%s: enqueued.", check_info)


    def update_activity_info_after_check(self, domain_name, domain_owner, record_id, check_result, check_result_details):
        check_info = f"Updating '{self.check_name}' check for domain '{domain_name}' with record ID '{record_id}'"
        logging.info(check_info)

        fields = {
            self.check_field_id: check_result.value
        }

        try:
            response = self.activityinfo_data.update_record(
                record_id=record_id,
                form_id=self.activityinfo_data.resource_ids.get('Domains'),
                fields=fields,
                parent_id=None  # or the appropriate parent ID if applicable
            )
            # Ensuring response is checked correctly for status
            if response and response.status_code == 200:
                logging.info(f"Successfully updated activity info for Domain '{domain_name}'")
            else:
                # Better error detail if response is available
                if response:
                    logging.error(f"Failed to update activity info for Domain '{domain_name}'. Status Code: {response.status_code}")
                else:
                    logging.error(f"Failed to update activity info for Domain '{domain_name}' due to no response.")
        except requests.RequestException as e:
            logging.error(f"Request failed for Domain '{domain_name}'. Exception: {str(e)}")
        except Exception as e:
            logging.exception(f"Unexpected error occurred while updating Domain '{domain_name}': {str(e)}")


    @abstractmethod
    def check_domain(self, domain_name: str, **kwargs) -> (CheckResult, dict):
        """
        Abstract method that should perform the specific check, to be overriden in each concrete child class.

        Args:
            domain_name: name of the domain to check, mandatory
        Keyword Args:
            record_id: record ID of the domain to check (typically fetched from ActivityInfo), optional
            domain_owner: owner of the domain to check, optional (empty default)
        Returns:
            a 2-tuple with the check result (as instance of enum class 'CheckResult')
            and a dictionary containing extra info details for the executed check, with error message(s) if any occurred
        """
        raise NotImplementedError("This method should be overridden and implemented in the child class!")


# Common static utility functions:


def fetch_http_head_response(url: str, timeout: int = HTTP_REQUEST_TIMEOUT,
                             **kwargs) -> (requests.Response, Optional[str]):
    """
    For the given URL, try to fetch the response to an HTTP HEAD request.

    Args:
        url: the URL
        timeout: (optional) How many seconds to wait for the server to send data
        kwargs: any extra options for the HTTP HEAD request
    Returns:
        a 2-tuple with the HTTP response if succeeded (or <None> if failed)
        and some extracted exception cause info text if failed (or <None> if succeeded)
    """
    return _fetch_http_response(url=url, timeout=timeout, fetch_request_method=requests.head, **kwargs)


def fetch_http_get_response(url: str, timeout: int = HTTP_REQUEST_TIMEOUT,
                            **kwargs) -> (requests.Response, Optional[str]):
    """
    For the given URL, try to fetch the response to an HTTP GET request.

    Args:
        url: the URL
        timeout: (optional) How many seconds to wait for the server to send data
        kwargs: any extra options for the HTTP GET request
    Returns:
        a 2-tuple with the HTTP response if succeeded (or <None> if failed)
        and some extracted exception cause info text if failed (or <None> if succeeded)
    """
    return _fetch_http_response(url=url, timeout=timeout, fetch_request_method=requests.get, **kwargs)


def _fetch_http_response(url: str, timeout: int = HTTP_REQUEST_TIMEOUT, fetch_request_method: Callable = requests.get,
                         **kwargs) -> (requests.Response, Optional[str]):
    """
    For the given URL, try to fetch the response to an HTTP request (GET or HEAD).

    Args:
        url: the URL
        timeout: (optional) How many seconds to wait for the server to send data
        fetch_request_method: (optional) fetch method to use with `requests.request`
        kwargs: any extra options for the HTTP GET request
    Returns:
        a 2-tuple with the HTTP response if succeeded (or <None> if failed)
        and some extracted exception cause info text if failed (or <None> if succeeded)

    Note:
        Internal private function not to be used outside of this script, as alas
        it looks quite cumbersome in current Python v3.12- to properly enforce the signature of the function in argument
        (so just using basic function type `Callable` with no argument nor return types).
    """
    # Note: not strictly checking for `isinstance(response, requests.Response)` as unit tests may use a raw mock object
    try:
        response = fetch_request_method(url=url, timeout=timeout, **kwargs)
        if isinstance(response, requests.Response):
            response.raise_for_status()
        return response, None
    except requests.exceptions.RequestException as e:
        exception = None
        try:
            exception = e.args[0].reason.__cause__
        except (TypeError, AttributeError, IndexError):
            pass
        if exception is None or not str(exception):
            try:
                exception = e.args[0].reason
            except (TypeError, AttributeError, IndexError):
                pass
        if exception is None or not str(exception):
            exception = e
        exception_info = str(exception)
        return None, exception_info


def fetch_https_or_http_headers(domain_name: str,
                                **kwargs) -> (requests.structures.CaseInsensitiveDict, Optional[str]):
    """
    For the given domain name, try to fetch HTTP headers via an HTTP GET request,
    using protocol "https" or if unsuccessful using protocol "http".

    Args:
        domain_name: the domain name
        kwargs: any extra options for the HTTP request head call
    Returns:
        a 2-tuple with the HTTP response headers for the first succeeded
        attempt (or <None> if all failed) and some extracted exception cause
        info text if all attempts failed (or <None> if any succeeded)
    """
    for protocol in ["https", "http"]:
        response, error_message = fetch_http_get_response(
            url=f"{protocol}://{domain_name}", **kwargs
        )
        if response is not None:
            return response.headers, error_message

    return None, error_message


def get_http_header_directive(http_headers: requests.structures.CaseInsensitiveDict, header_name: str,
                              header_directive_name: str) -> Optional[str]:
    """
    From a given HTTP header, extract a specific HTTP header directive if it is present, or return <None> otherwise.

    Args:
        http_headers: the HTTP headers to extract the directive from
        header_name: the name of the HTTP header to extract the directive from
        header_directive_name: the name of the HTTP header directive to extract

    Returns:
        the HTTP header directive value if succeeded (or <None> if failed)
    """
    if (not http_headers or not header_name or not header_directive_name or
            not isinstance(http_headers, requests.structures.CaseInsensitiveDict) or
            len(http_headers) <= 0 or header_name not in http_headers):
        return None
    header_directives = http_headers[header_name].split(";")
    for header_directive_str in header_directives:
        header_directive_str = header_directive_str.strip()
        try:
            header_directive_str_name, header_directive_str_value = header_directive_str.split(None, 1)
        except ValueError:
            header_directive_str_name = header_directive_str
            header_directive_str_value = ""
        if header_directive_str_name.lower() == header_directive_name.lower():
            return header_directive_str_value
    return None


def lookup_ip_addresses(domain_name: str) -> list[str]:
    """
    Resolves the given domain name to its corresponding IP addresses using `socket.getaddrinfo()`.

    Args:
        domain_name (str): The domain name to resolve.

    Returns:
        list: A list of IP addresses as strings if resolution is successful, an empty list otherwise.
    """
    try:
        # Fetches address information
        addr_info = socket.getaddrinfo(host=domain_name, port=None)
        # Extracts the IP addresses from the address information
        ip_addresses = [info[4][0] for info in addr_info]
        # Removes duplicates
        unique_ips = list(set(ip_addresses))
        return unique_ips
    except socket.gaierror as e:
        logging.exception("An exception occurred while resolving domain '%s': '%s'!", domain_name, e)
        return []
