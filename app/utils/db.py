# app/utils/db.py
import sqlite3
from contextlib import contextmanager
from app.utils.config import config

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(config["DATABASE"])
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()