import sqlite3
from adpa import init_db
import os

db_path = "test_schema.db"
if os.path.exists(db_path):
    os.remove(db_path)

init_db(db_path)

conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='web_users'")
print("web_users table exists:", c.fetchone() is not None)
conn.close()
os.remove(db_path)
