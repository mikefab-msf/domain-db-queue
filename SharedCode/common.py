# SharedCode/common.py

import json
import logging
from azure.functions import HttpRequest, HttpResponse
from .activityinfo import ActivityInfoData

def parse_request(req: HttpRequest):
    """Parses the HTTP request and returns domains."""
    try:
        data = req.get_json()
        logging.info("Received data: %s", data)
        
        domain_list_str = data.get('body')
        if isinstance(domain_list_str, str):
            domains = json.loads(domain_list_str)
        elif isinstance(domain_list_str, list):
            domains = domain_list_str
        else:
            raise ValueError("The 'body' key must be a list or a string representation of a list.")
        
        logging.info("Received domains: %s", domains)
        return domains

    except json.JSONDecodeError as e:
        logging.error("JSON decoding error: %s", e)
        raise

def initialize_activity_info():
    """Initializes the ActivityInfoData."""
    return ActivityInfoData()

def handle_exception(e: Exception) -> HttpResponse:
    """Creates an HttpResponse for the given exception."""
    if isinstance(e, json.JSONDecodeError):
        return HttpResponse(body=f"JSON decoding error: {str(e)}", status_code=400)
    else:
        logging.exception("An error occurred: %s", str(e))
        return HttpResponse(body=f"An error occurred: {str(e)}", status_code=500)
