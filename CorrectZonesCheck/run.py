import logging

import json
from azure.functions import HttpRequest, HttpResponse
from SharedCode.abstract_template import AbstractTemplateCheck, CheckResult
from SharedCode.activityinfo import ActivityInfoData
from SharedCode.common import parse_request, initialize_activity_info, handle_exception

ORG_DOMAIN_SUFFIX = "msf.org"

class CorrectZonesCheck(AbstractTemplateCheck):

    def __init__(self, activityinfo_data: ActivityInfoData, **kwargs):
        super().__init__(check_name="Brand safety", activityinfo_data=activityinfo_data, **kwargs)
        self.country_zones = activityinfo_data.zones_lookup

    def check_domain(self, domain_name: str, **kwargs) -> (CheckResult, dict):
        domain_owner = kwargs.get("domain_owner", "")
        result = None
        data = None
        logging.info("Class '%s': checking domain name '%s', with DOMAIN OWNER: '%s'",
                      __class__.__name__, domain_name, domain_owner)
        zones = self.country_zones.get(domain_owner, []) if domain_owner else []
        logging.info("class '%s': zones for domain owner '%s': '%s'",
                      __class__.__name__, domain_owner, zones)

        if domain_name == ORG_DOMAIN_SUFFIX or domain_name.endswith("." + ORG_DOMAIN_SUFFIX):
            result = CheckResult.OK
            data = "Correct zone"
            return result, {"data": data}

        if not domain_owner or len(domain_owner) <= 0:
            result = CheckResult.NOK
            data = "Domain owner not defined!"
            return result, {"data": data}

        if not zones:
            result = CheckResult.NOK
            data = f"No zones found for owner '{domain_owner}'!"
            return result, {"data": data}

        for zone in zones:
            if domain_name == zone or domain_name.endswith(f".{zone}"):
                result = CheckResult.OK
                data = f"Correct zone for owner '{domain_owner}'."
                return result, {"data": data}

        result = CheckResult.NOK
        data = f"Incorrect zone for owner '{domain_owner}', does not end with one of: {zones}!"
        return result, {"data": data}

def main(req: HttpRequest) -> HttpResponse:
    try:
        domains = parse_request(req)
        activity_data = initialize_activity_info()
        check = CorrectZonesCheck(activity_data)
        results = check.check_all_domains(domains)
        return HttpResponse(body=str(results), status_code=200)
    except Exception as e:
        return handle_exception(e)

