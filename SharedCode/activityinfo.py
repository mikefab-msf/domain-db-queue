"""
MSF-OCB Domain DB Checks (2024-01a)
**IMPORTANT**
For Internal Use Only -- NO WARRANTY! -- Risk of DATA LOSS/CORRUPTION/DISCLOSURE!!
Please first carefully read the instructions in the file "README.md" provided with this project.

Custom ActivityInfo database access module
"""

import json
import logging
import os
from typing import Any, Optional
from collections import defaultdict
import requests

from SharedCode.helpers import is_invalid_param_string

ENV_VARS_PREFIX = "ACTIVITYINFO_"

HTTP_REQUEST_TIMEOUT = 10  # Default timeout for HTTP requests (in seconds)


class ActivityInfoData:
    """Class representing gateway to database provider"""
    def __init__(
            self,
            base_url: str = None,
            api_token: str = None,
            db_id: str = None,
            **kwargs
    ):
        logging.info("class '%s': initializing...", __class__.__name__)

        self.base_url = None
        self.api_token = None
        self.db_id = None
        self.db_url = None
        self.request_headers = None
        self.domains_rows = []
        self.resource_ids = {}
        self.schemas = {}
        self.checks_lookup = {}
        self.zones_lookup = {}
        self.check_domain_hash = {}

        self.for_test_only: bool = kwargs.get("for_test_only", False)
        if self.for_test_only:
            logging.info("class '%s': stopping initialization (mode 'for_test_only' is %s)",
                          __class__.__name__, self.for_test_only)
            return

        self.base_url = base_url
        if is_invalid_param_string(self.base_url):
            self.base_url = os.getenv(f"{ENV_VARS_PREFIX}BASE_URL")
        if is_invalid_param_string(self.base_url):
            raise ValueError("Missing ActivityInfo base URL!")
        logging.info("class '%s': initializing: ActivityInfo base URL: '%s'",
                      __class__.__name__, self.base_url)

        self.api_token = api_token
        if is_invalid_param_string(self.api_token):
            self.api_token = os.getenv(f"{ENV_VARS_PREFIX}API_TOKEN")
        if is_invalid_param_string(self.api_token):
            raise ValueError("Missing ActivityInfo API token!")
        logging.info("class '%s': initializing: ActivityInfo API token: '%s'",
                      __class__.__name__, self.api_token)

        self.db_id = db_id
        if is_invalid_param_string(self.db_id):
            self.db_id = os.getenv(f"{ENV_VARS_PREFIX}DB_ID")
        if is_invalid_param_string(self.db_id):
            raise ValueError("Missing ActivityInfo database ID!")
        logging.info("class '%s': initializing: ActivityInfo database ID: '%s'",
                      __class__.__name__, self.db_id)

        self.db_url = f"{self.base_url}/resources/databases/{self.db_id}"
        self.request_headers = {'Authorization': f'Bearer {self.api_token}'}

        logging.info("class '%s': initializing: get_data_from_activityinfo()",
                      __class__.__name__, )
        activityinfo_data = self.get_data_from_activityinfo()

        logging.info("class '%s': initializing: get resource_ids, schemas",
                      __class__.__name__, )
        if activityinfo_data:
            resources = activityinfo_data.get("resources", [])
            for resource in resources:
                label = resource.get("label")
                resource_id = resource.get("id")
                if label and resource_id and resource_id != 'reference':
                    self.resource_ids[label] = resource_id
                    self.schemas[resource_id] = self.fetch_resource_schema(resource_id)

        if is_invalid_param_string(self.resource_ids.get("Domains")):
            raise RuntimeError(f"Failed to get the domains ID from DB '{self.db_url}'!")

        logging.info("class '%s': initializing: fetch_reference_data_rows()",
                      __class__.__name__, )
        reference_data_sets = self.fetch_reference_data_rows()
        self.checks_lookup = reference_data_sets['checks_lookup']
        self.zones_lookup = reference_data_sets['zones_lookup']

        if self.checks_lookup is None or len(self.checks_lookup) <= 0:
            raise RuntimeError(f"No checks found in DB '{self.db_url}'!")

        logging.info("class '%s': initializing: fetch_all_domains_rows()",
                      __class__.__name__, )
        self.domains_rows = self.fetch_all_domains_rows()
     
        self.check_domain_hash = self.create_check_domain_hash()
        if self.domains_rows is None or len(self.domains_rows) <= 0:
            raise RuntimeError(f"No domains found in DB '{self.db_url}'!")

        logging.info("class '%s': initialized.", __class__.__name__)

    def fail_if_test_only_mode(self) -> None:
        """
        Checks if the current mode is set to 'for_test_only'.
        """
        if self.for_test_only:
            raise NotImplementedError(
                f"Mode 'for_test_only' is {self.for_test_only}: action unsupported!"
            )

    def make_request(self, endpoint: str, method: str = "GET", data: Optional[Any] = None) -> Optional[Any]:
        self.fail_if_test_only_mode()

        url = (
            f"{self.base_url}/{endpoint}"
            if not endpoint.startswith(f"{self.base_url}/")
            else endpoint
        )

        response = requests.request(
            method, url, headers=self.request_headers,
            json=data, timeout=HTTP_REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            if response.text:  # Check if the response actually contains text
                logging.info(
                    "Received response text (length: %s) from URL '%s'.",
                    len(response.text), url)

                try:
                    return json.loads(response.text)
                except json.JSONDecodeError as e:
                    logging.exception(
                        "Failed to decode JSON response text from URL '%s' due to exception '%s'!",
                        url, e)

                    return None
            else:
                logging.info(
                    "Received empty response text from URL '%s'.",
                    url)

                return response.text
        else:
            logging.error(
                "Failed to get data from URL '%s' with status '%s'!",
                url, response.status_code)

            return None

    def update_record(self, record_id: str, form_id: str, fields: dict, parent_id: str, deleted: bool = False) -> None:
        self.fail_if_test_only_mode()
        endpoint = "resources/update"
        data = {
            "changes": [
                {
                    "formId": form_id,
                    "recordId": record_id,
                    "parentRecordId": parent_id,
                    "fields": fields,
                    "deleted": deleted
                }
            ]
        }

        logging.info(f"Attempting to update record '{record_id}' in form '{form_id}' with data: {data}")

        try:
            response = self.make_request(endpoint=endpoint, method="POST", data=data)
            if not response or not hasattr(response, 'status_code') or response.status_code != 200:
                error_details = 'No response' if not response else f"Unexpected status code: {response.status_code}"
                logging.error(f"Exception occurred while updating record '{record_id}' in form '{form_id}': {error_details}")
                return  # Exit the function to avoid executing success logic
            logging.info(f"Successfully updated the record '{record_id}' in form '{form_id}'.")
            # Check if response is a requests.Response object and has a 200 status_code
            if isinstance(response, requests.Response) and response.status_code == 200:
                logging.info(f"Successfully updated the record '{record_id}' in form '{form_id}'.")
            else:
                # Provide more meaningful error logging depending on whether a response was received
                if response is None:
                    logging.error(f"Failed to update the record '{record_id}' in form '{form_id}': No response received.")
                else:
                    logging.error(f"Failed to update the record '{record_id}' in form '{form_id}': Status code: {response.status_code}.")

        except Exception as e:
            logging.error(f"Exception occurred while updating record '{record_id}' in form '{form_id}': {str(e)}. Here is the endpoint: {endpoint}")



    def get_data_from_activityinfo(self) -> Optional[Any]:
        self.fail_if_test_only_mode()
        return self.make_request(endpoint=self.db_url)

    def fetch_resource_schema(self, form_id) -> Optional[dict]:
        self.fail_if_test_only_mode()
        endpoint = f"resources/form/{form_id}/schema"

        data = self.make_request(endpoint=endpoint)
        field_to_id = {}
        if data:
            elements = data.get('elements', [])

            for element in elements:
                label = element.get('label')
                id_value = element.get('id')
                if label is not None:
                    field_to_id[label] = id_value
        return field_to_id

    def fetch_reference_data_rows(self) -> dict:
        """
        Retrieves and structures reference data from ActivityInfo for 'checks' and 'zones'.
        It creates 'checks_lookup' as a name-ID mapping and 'zones_lookup' as a
        name-domain list mapping.

        Returns:
            A dictionary with keys 'checks_lookup' and 'zones_lookup'.
        """
        self.fail_if_test_only_mode()

        checks_endpoint = f"resources/form/{self.resource_ids.get('Checks')}/query"

        domain_field_id = self.schemas[self.resource_ids['TLDs']]['Domain']

        zones_endpoint = f"resources/form/{self.resource_ids.get('TLDs')}/query?" \
                         f"Parent+Name=%40parent.name&Domain={domain_field_id}"

        checks_data = self.make_request(endpoint=checks_endpoint)
        zones_data = self.make_request(endpoint=zones_endpoint)

        checks_rows = [
            (row['Name'], row['@id']) for row in checks_data
        ] if checks_data else []
        zones_rows = [
            (row['Parent Name'], row['Domain']) for row in zones_data
        ] if zones_data else []

        zones_lookup = defaultdict(list)
        for zone_name, domain in zones_rows:
            zones_lookup[zone_name].append(domain)

        return {
            'checks_lookup': {row[0]: row[1] for row in checks_rows},
            'zones_lookup': zones_lookup
        }

    def fetch_all_results_rows(self) -> Optional[list[dict]]:
        self.fail_if_test_only_mode()
        endpoint = f"resources/form/{self.resource_ids.get('Results')}/query"
        data = self.make_request(endpoint=endpoint)

        return [
            (row['Parent.DOMAIN'], row['Checks.ID'], row['@id']) for row in data
        ] if data else None

    def create_check_domain_hash(self) -> dict:
        results_rows = self.fetch_all_results_rows()
        if results_rows is None:
            return {}

        check_domain_hash = {}
        for row in results_rows:
            unique_key = f"{row[0]}-{row[1]}"
            check_domain_hash[unique_key] = row[2]
        return check_domain_hash

    def fetch_all_domains_rows(self) -> Optional[list[(str, str, str)]]:
        self.fail_if_test_only_mode()
        endpoint = f"resources/form/{self.resource_ids.get('Domains')}/query"
        data = self.make_request(endpoint=endpoint)

        return [
            (row['DOMAIN'], row['OWNER.Name'], row['@id']) for row in data
        ] if data else None

    def fetch_ip_row(self, parent_id, ip_address) -> Optional[Any]:
        self.fail_if_test_only_mode()
        endpoint = "resources/query/columns"
        field_id = self.schemas[self.resource_ids['IP addresses']]['IP']
        data = {
            "rowSources": [{"rootFormId": self.resource_ids['IP addresses']}],
            "columns": [
                {"id": "$$id", "expression": "_id"}
            ],
            "truncateStrings": True,
            "filter": f"@parent == \"{parent_id}\" && ISNUMBER(SEARCH(\"{ip_address}\", {field_id}))"
        }
        return self.make_request(endpoint=endpoint, method="POST", data=data)
