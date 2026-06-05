import sqlite3
import os
import subprocess

def test_admin_creation_non_interactive():
    db_path = "analysis.db"
    creds_file = "admin_credentials.txt"

    # clean up
    if os.path.exists(db_path):
        os.remove(db_path)
    if os.path.exists(creds_file):
        os.remove(creds_file)

    # create mock potfile and ntds file
    open('mock.potfile', 'w').close()
    open('mock.ntds', 'w').close()

    result = subprocess.run(['python', 'adpa.py', '-n', 'mock.ntds', '-p', 'mock.potfile'], capture_output=True, text=True)

    # Check that it executed correctly
    assert result.returncode == 0
    assert "Random administrator credentials have been generated and saved securely" in result.stdout

    # Check that admin_credentials.txt exists
    assert os.path.exists(creds_file)

    # Check permissions
    st = os.stat(creds_file)
    assert oct(st.st_mode & 0o777) == '0o600'

    # Check DB
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT username, must_change_password FROM web_users WHERE username='Administrator'")
    user = c.fetchone()
    assert user is not None
    assert user[0] == 'Administrator'
    assert user[1] == 1
    conn.close()

if __name__ == '__main__':
    test_admin_creation_non_interactive()
    print("Test passed.")
