import logging

from .run import main

def init_func(req) -> None:
    logging.info('Python HTTP trigger function processed a request.')
    return main(req)
