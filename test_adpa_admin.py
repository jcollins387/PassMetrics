import sqlite3
import os
import subprocess

db_path = "analysis.db"
# create mock potfile and ntds file
open('mock.potfile', 'w').close()
open('mock.ntds', 'w').close()

result = subprocess.run(['python', 'adpa.py', '-n', 'mock.ntds', '-p', 'mock.potfile'], capture_output=True, text=True)
print(result.stdout)
print(result.stderr)

conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute("SELECT username, must_change_password FROM web_users WHERE username='Administrator'")
user = c.fetchone()
print(f"Admin user found: {user}")
conn.close()
