import azure.functions as func
import logging

def main(msg: func.QueueMessage) -> None:
    logging.info('Python Queue trigger processed a message: %s', msg.get_body().decode('utf-8'))
