# /utils/logger.py
import logging

def setup_logging(config):
    logging.basicConfig(
        level=getattr(logging, config["LOG_LEVEL"]),
        format=config["LOG_FORMAT"]
    )