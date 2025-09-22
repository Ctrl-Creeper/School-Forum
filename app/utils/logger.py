# app/utils/logger.py
import logging

# 初始化 logger
logger = logging.getLogger("school_forum")

def setup_logging(config):
    logger.setLevel(getattr(logging, config["LOG_LEVEL"]))
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(config["LOG_FORMAT"]))
    logger.addHandler(handler)