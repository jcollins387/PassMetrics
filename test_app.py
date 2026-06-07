from unittest.mock import MagicMock
import pytest
import sqlite3
import os
from flask import g
from app import app, get_db, query_db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    # Create an empty test database
    db_path = "test_analysis.db"
    app.config["DATABASE"] = db_path

    with app.app_context():
        # Setup basic tables to allow tests to run
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS users (
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
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            nt_hash TEXT,
            lm_hash TEXT,
            is_history INTEGER,
            cracked_password TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS user_groups (
            user_id INTEGER,
            group_name TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS policy_violations (
            user_id INTEGER,
            policy_name TEXT,
            reason TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS shared_hashes (
            nt_hash TEXT,
            cracked_password TEXT,
            count INTEGER,
            shared_by TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS web_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            must_change_password INTEGER DEFAULT 0
        )""")
        # We need a user to bypass change_password redirect
        from werkzeug.security import generate_password_hash

        hashed_pw = generate_password_hash("password123")
        c.execute("INSERT INTO web_users (id, username, password_hash, must_change_password) VALUES (1, 'testadmin', ?, 0)", (hashed_pw,))
        conn.commit()
        conn.close()

    with app.test_client() as client:
        yield client

    os.remove(db_path)


def test_require_login_unauthenticated_allowed_route(client):
    response = client.get("/login")
    assert response.status_code == 200


def test_require_login_unauthenticated_protected_route(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login?next=http" in response.headers["Location"] and "localhost" in response.headers["Location"]


def test_require_login_authenticated_no_change_needed(client):
    # Log in as testadmin who has must_change_password = 0
    with client.session_transaction() as sess:
        sess["user_id"] = 1
    # We'll test against /mappings instead of / to avoid needing to mock dashboard DB queries
    response = client.get("/mappings")
    assert response.status_code == 200


def test_require_login_authenticated_change_needed_protected_route(client):
    # Update testadmin to must_change_password = 1
    with client.application.app_context():
        from app import get_db

        db = get_db()
        db.execute("UPDATE web_users SET must_change_password = 1 WHERE id = 1")
        db.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = 1

    response = client.get("/mappings")
    assert response.status_code == 302
    assert response.headers["Location"] == "/change_password"

    # Revert testadmin to must_change_password = 0 for other tests
    with client.application.app_context():
        db = get_db()
        db.execute("UPDATE web_users SET must_change_password = 0 WHERE id = 1")
        db.commit()


def test_require_login_authenticated_change_needed_change_password_route(client):
    # Update testadmin to must_change_password = 1
    with client.application.app_context():
        from app import get_db

        db = get_db()
        db.execute("UPDATE web_users SET must_change_password = 1 WHERE id = 1")
        db.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = 1

    response = client.get("/change_password")
    assert response.status_code == 200

    # Revert testadmin to must_change_password = 0 for other tests
    with client.application.app_context():
        db = get_db()
        db.execute("UPDATE web_users SET must_change_password = 0 WHERE id = 1")
        db.commit()


def test_require_login_authenticated_change_needed_logout_route(client):
    # Update testadmin to must_change_password = 1
    with client.application.app_context():
        from app import get_db

        db = get_db()
        db.execute("UPDATE web_users SET must_change_password = 1 WHERE id = 1")
        db.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = 1

    response = client.get("/logout")
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"

    # Revert testadmin to must_change_password = 0 for other tests
    with client.application.app_context():
        db = get_db()
        db.execute("UPDATE web_users SET must_change_password = 0 WHERE id = 1")
        db.commit()


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
    response = client.get("/mappings?search=test")
    assert response.status_code == 200
    assert b"test_user" in response.data
    assert b"other_user" not in response.data

    # Empty search
    response = client.get("/mappings")
    assert response.status_code == 200
    assert b"test_user" in response.data
    assert b"other_user" in response.data

    # SQL Injection attempt (should fail to inject or return 500 if vulnerable)
    response = client.get('/mappings?search=test" OR 1=1;--')
    assert response.status_code == 200  # App should handle it gracefully
    assert b"other_user" not in response.data  # Shouldn't leak due to injection


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

    response = client.get("/high_value")
    assert response.status_code == 200
    assert b"test_user" in response.data

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

    response = client.get("/history")
    assert response.status_code == 200
    assert b"historypass" in response.data
    assert b"otherhistorypass" in response.data


def test_get_secret_key_from_env():
    from app import get_secret_key
    import os

    os.environ["FLASK_SECRET_KEY"] = "test_env_key"
    key = get_secret_key()
    assert key == b"test_env_key"
    del os.environ["FLASK_SECRET_KEY"]


def test_get_secret_key_random_fallback():
    from app import get_secret_key
    import os

    if "FLASK_SECRET_KEY" in os.environ:
        del os.environ["FLASK_SECRET_KEY"]
    key1 = get_secret_key()
    key2 = get_secret_key()
    assert len(key1) == 24
    assert len(key2) == 24
    assert key1 != key2  # random keys should be different
    assert not os.path.exists(".flask_secret")  # should not create file


def test_get_db_creates_and_caches_connection():
    with app.app_context():
        # Clean up g if it was left dirty
        if hasattr(g, "_database"):
            del g._database

        db1 = get_db()
        db2 = get_db()

        # Verify it returns a connection
        assert isinstance(db1, sqlite3.Connection)

        # Verify it caches the connection
        assert db1 is db2

        # Verify row_factory is set
        assert db1.row_factory == sqlite3.Row


def test_get_db_uses_config_path(client):
    with app.app_context():
        if hasattr(g, "_database"):
            del g._database

        # App config 'DATABASE' should be 'test_analysis.db' via the client fixture
        expected_path = app.config.get("DATABASE")

        # We can mock sqlite3.connect just to assert the path argument
        import unittest.mock as mock

        with mock.patch("sqlite3.connect") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            get_db()
            mock_connect.assert_called_once_with(expected_path)


def test_get_db_uses_fallback_path():
    with app.app_context():
        if hasattr(g, "_database"):
            del g._database

        # Temporarily remove DATABASE from config
        original_db = app.config.pop("DATABASE", None)

        try:
            import unittest.mock as mock

            with mock.patch("sqlite3.connect") as mock_connect:
                mock_connect.return_value = mock.MagicMock()
                get_db()
                # Should fall back to the global DATABASE variable which is 'analysis.db'
                from app import DATABASE

                mock_connect.assert_called_once_with(DATABASE)
        finally:
            # Restore config
            if original_db is not None:
                app.config["DATABASE"] = original_db


def test_close_connection_with_db():
    mock_db = MagicMock()
    with app.app_context():
        g._database = mock_db

    mock_db.close.assert_called_once()


def test_close_connection_without_db():
    with app.app_context():
        pass  # g._database is not set, should not raise an exception


def test_secure_session_configuration():
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_open_redirect_login_unsafe_url(client):
    app.before_request_funcs[None] = []
    response = client.post(
        "/login?next=http://malicious.com", data={"username": "testadmin", "password": "password123"}, follow_redirects=False
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/"  # Should redirect to dashboard, not malicious.com


def test_open_redirect_login_safe_url(client):
    app.before_request_funcs[None] = []
    response = client.post("/login?next=/mappings", data={"username": "testadmin", "password": "password123"}, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"] == "/mappings"  # Should redirect to the safe relative URL


def test_login_no_next_url(client):
    app.before_request_funcs[None] = []
    response = client.post("/login", data={"username": "testadmin", "password": "password123"}, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"] == "/"  # Should redirect to dashboard by default


def test_login_rate_limiting(client):
    got_429 = False
    for _ in range(10):
        response = client.post("/login", data={"username": "testadmin", "password": "wrong_password"})
        if response.status_code == 429:
            got_429 = True
            break

    assert got_429, "Expected to eventually hit a 429 Too Many Requests response"


def test_query_db_multiple_results(client):
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("DELETE FROM users")
        c.execute("INSERT INTO users (domain, username, original_domain) VALUES ('d1', 'u1', 'o1')")
        c.execute("INSERT INTO users (domain, username, original_domain) VALUES ('d2', 'u2', 'o2')")
        db.commit()

        results = query_db("SELECT username FROM users ORDER BY username")
        assert len(results) == 2
        assert results[0]["username"] == "u1"
        assert results[1]["username"] == "u2"


def test_query_db_single_result(client):
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("DELETE FROM users")
        c.execute("INSERT INTO users (domain, username, original_domain) VALUES ('d1', 'u1', 'o1')")
        c.execute("INSERT INTO users (domain, username, original_domain) VALUES ('d2', 'u2', 'o2')")
        db.commit()

        result = query_db("SELECT username FROM users WHERE domain = ?", ["d2"], one=True)
        assert result is not None
        assert result["username"] == "u2"


def test_query_db_no_results(client):
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("DELETE FROM users")
        db.commit()

        # one=False should return empty list
        results = query_db("SELECT username FROM users")
        assert results == []

        # one=True should return None
        result = query_db("SELECT username FROM users", one=True)
        assert result is None


def test_query_db_with_args(client):
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("DELETE FROM users")
        c.execute("INSERT INTO users (domain, username, original_domain) VALUES ('d1', 'u1', 'o1')")
        db.commit()

        # Test valid args
        result = query_db("SELECT original_domain FROM users WHERE domain = ? AND username = ?", ["d1", "u1"], one=True)
        assert result is not None
        assert result["original_domain"] == "o1"

        # Test invalid args (no match)
        result = query_db("SELECT original_domain FROM users WHERE domain = ? AND username = ?", ["d1", "unknown"], one=True)
        assert result is None


def test_asreproastable_route(client):
    app.before_request_funcs[None] = []

    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM hashes")

        # User 1: asreproastable=1, enabled=1 (Should appear)
        c.execute("INSERT INTO users (id, domain, username, original_domain, asreproastable, enabled) VALUES (1, 'test_domain1', 'test_user1', 'test_orig1', 1, 1)")
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (1, 0, 'cracked_pass1')")

        # User 2: asreproastable=1, enabled=0 (Should NOT appear)
        c.execute("INSERT INTO users (id, domain, username, original_domain, asreproastable, enabled) VALUES (2, 'test_domain2', 'test_user2', 'test_orig2', 1, 0)")
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (2, 0, 'cracked_pass2')")

        # User 3: asreproastable=0, enabled=1 (Should NOT appear)
        c.execute("INSERT INTO users (id, domain, username, original_domain, asreproastable, enabled) VALUES (3, 'test_domain3', 'test_user3', 'test_orig3', 0, 1)")
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (3, 0, 'cracked_pass3')")

        db.commit()

    response = client.get("/asreproastable")

    assert response.status_code == 200

    # Check that User 1 appears
    assert b"test_domain1" in response.data
    assert b"test_user1" in response.data
    assert b"cracked_pass1" in response.data

    # Check that User 2 does not appear
    assert b"test_domain2" not in response.data
    assert b"test_user2" not in response.data
    assert b"cracked_pass2" not in response.data

    # Check that User 3 does not appear
    assert b"test_domain3" not in response.data
    assert b"test_user3" not in response.data
    assert b"cracked_pass3" not in response.data
