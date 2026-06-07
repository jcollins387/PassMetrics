import pytest
import sqlite3
import json
import os
from flask import g
from app import app, get_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    # Create an empty test database
    db_path = 'test_analysis.db'
    app.config['DATABASE'] = db_path

    with app.app_context():
        # Setup basic tables to allow tests to run
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            username TEXT,
            original_domain TEXT,
            pwdlastset INTEGER,
            pwdneverexpires INTEGER,
            passwordnotreqd INTEGER,
            kerberoastable INTEGER,
            asreproastable INTEGER,
            enabled INTEGER
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            nt_hash TEXT,
            lm_hash TEXT,
            is_history INTEGER,
            cracked_password TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS user_groups (
            user_id INTEGER,
            group_name TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS policy_violations (
            user_id INTEGER,
            policy_name TEXT,
            reason TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS shared_hashes (
            nt_hash TEXT,
            cracked_password TEXT,
            count INTEGER,
            shared_by TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS web_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            must_change_password INTEGER DEFAULT 0
        )''')
        # We need a user to bypass change_password redirect
        c.execute("INSERT INTO web_users (id, username, password_hash, must_change_password) VALUES (1, 'testadmin', 'hash', 0)")
        conn.commit()
        conn.close()

    with app.test_client() as client:
        yield client

    os.remove(db_path)

def test_mappings_search_injection(client):
    app.before_request_funcs[None] = []

    # Setup test data
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("DELETE FROM users")
        c.execute("INSERT INTO users (domain, username, original_domain) VALUES ('test_domain', 'test_user', 'test_orig')")
        c.execute("INSERT INTO users (domain, username, original_domain) VALUES ('other_domain', 'other_user', 'other_orig')")
        db.commit()

    # Normal search
    response = client.get('/mappings?search=test')
    assert response.status_code == 200
    assert b'test_user' in response.data
    assert b'other_user' not in response.data

    # Empty search
    response = client.get('/mappings')
    assert response.status_code == 200
    assert b'test_user' in response.data
    assert b'other_user' in response.data

    # SQL Injection attempt (should fail to inject or return 500 if vulnerable)
    response = client.get('/mappings?search=test" OR 1=1;--')
    assert response.status_code == 200 # App should handle it gracefully
    assert b'other_user' not in response.data # Shouldn't leak due to injection

def test_high_value_groups_injection(client):
    app.before_request_funcs[None] = []
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('high_value_groups', '[\"Domain Admins\", \"Enterprise Admins\"]')")
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM hashes")
        c.execute("DELETE FROM user_groups")
        c.execute("INSERT INTO users (id, domain, username, original_domain) VALUES (1, 'test_domain', 'test_user', 'test_orig')")
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (1, 0, 'password')")
        c.execute("INSERT INTO user_groups (user_id, group_name) VALUES (1, 'Domain Admins')")
        db.commit()

    response = client.get('/high_value')
    assert response.status_code == 200
    assert b'test_user' in response.data

    # Attempt injection via group parameter
    response = client.get('/high_value?group=Domain Admins") OR 1=1--')
    assert response.status_code == 200

def test_history_injection(client):
    app.before_request_funcs[None] = []
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM hashes")
        c.execute("INSERT INTO users (id, domain, username, original_domain) VALUES (1, 'test_domain', 'test_user', 'test_orig')")
        c.execute("INSERT INTO users (id, domain, username, original_domain) VALUES (2, 'other_domain', 'other_user', 'other_orig')")
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (1, 1, 'historypass')")
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (2, 1, 'otherhistorypass')")
        db.commit()

    response = client.get('/history')
    assert response.status_code == 200
    assert b'historypass' in response.data
    assert b'otherhistorypass' in response.data

def test_get_secret_key_from_env():
    from app import get_secret_key
    import os
    os.environ['FLASK_SECRET_KEY'] = 'test_env_key'
    key = get_secret_key()
    assert key == b'test_env_key'
    del os.environ['FLASK_SECRET_KEY']

def test_get_secret_key_random_fallback():
    from app import get_secret_key
    import os
    if 'FLASK_SECRET_KEY' in os.environ:
        del os.environ['FLASK_SECRET_KEY']
    key1 = get_secret_key()
    key2 = get_secret_key()
    assert len(key1) == 24
    assert len(key2) == 24
    assert key1 != key2 # random keys should be different
    assert not os.path.exists('.flask_secret') # should not create file

from unittest.mock import MagicMock

def test_close_connection_with_db():
    mock_db = MagicMock()
    with app.app_context():
        g._database = mock_db

    mock_db.close.assert_called_once()

def test_close_connection_without_db():
    with app.app_context():
        pass # g._database is not set, should not raise an exception

def test_secure_session_configuration():
    assert app.config['SESSION_COOKIE_HTTPONLY'] is True
    assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
