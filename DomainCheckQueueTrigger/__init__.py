# import azure.functions as func
# import logging

# def main(msg: func.QueueMessage) -> None:
#     logging.info('Python Queue trigger processed a message: %s', msg.get_body().decode('utf-8'))

import json
import logging
import azure.functions as func
from SharedCode.abstract_template import AbstractTemplateCheck
from SharedCode.activityinfo import ActivityInfoData

# Import all your check classes here
from CorrectZonesCheck.run import CorrectZonesCheck

def get_check_instance(check_name, activity_data):
    # Factory method to instantiate check classes based on the check_name
    if check_name == "Brand safety":
        return CorrectZonesCheck(activity_data)
    else:
        raise ValueError(f"Unsupported check name: {check_name}")

def main(msg: func.QueueMessage) -> None:
    try:
        message_body = msg.get_body().decode('utf-8')
        message = json.loads(message_body)

        check_name = message['check_name']
        domain_name = message['domain_name']
        domain_owner = message.get('domain_owner', '')
        record_id = message.get('record_id', '')

        logging.info(f"Received message to perform check: {check_name} for domain: {domain_name}")

        activity_data = ActivityInfoData()
        check_instance = get_check_instance(check_name, activity_data)

        logging.info(f"Check instance for '{check_name}' created. Performing check for domain: {domain_name}")

        check_result, check_result_details = check_instance.check_domain(domain_name, domain_owner=domain_owner, record_id=record_id)

        try:
            check_instance.update_activity_info_after_check(domain_name, domain_owner, record_id, check_result, check_result_details)
            logging.info(f"ActivityInfo updated successfully for domain '{domain_name}' after check.")
        except Exception as update_error:
            logging.error(f"Failed to update ActivityInfo for domain '{domain_name}' due to exception: {update_error}")
        
        logging.info(f"Check completed for domain '{domain_name}': Result - {check_result}, Details - {check_result_details}")

    except Exception as e:
        logging.error(f"Error processing queue message: {e}")
