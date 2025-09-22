# /utils/config.py
import yaml, logging

with open("config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)