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
    app.config["DB_KEY"] = "testkey"

    with app.app_context():
        # Setup basic tables to allow tests to run
        from pysqlcipher3 import dbapi2 as sqlite3

        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA key='testkey'")
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

    # Test wildcard escape (DoS protection)
    # '%' and '_' should be treated as literal characters, not wildcards
    response = client.get("/mappings?search=%")
    assert response.status_code == 200
    # Since no username contains literal '%', it shouldn't match everything
    assert b"test_user" not in response.data
    assert b"other_user" not in response.data

    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("INSERT INTO users (domain, username, original_domain) VALUES ('test_domain', 'user%name', 'test_orig')")
        c.execute("INSERT INTO users (domain, username, original_domain) VALUES ('test_domain', 'user_name', 'test_orig')")
        db.commit()

    response = client.get("/mappings?search=%")
    assert response.status_code == 200
    assert b"user%name" in response.data
    assert b"test_user" not in response.data

    response = client.get("/mappings?search=_")
    assert response.status_code == 200
    assert b"user_name" in response.data
    assert b"test_user" in response.data  # 'test_user' contains an underscore
    assert b"other_user" in response.data  # 'other_user' contains an underscore

    response = client.get("/mappings?search=\\")
    assert response.status_code == 200


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
        from pysqlcipher3 import dbapi2 as pysqlcipher3

        assert isinstance(db1, pysqlcipher3.Connection)

        # Verify it caches the connection
        assert db1 is db2

        # Verify row_factory is set
        assert db1.row_factory == pysqlcipher3.Row


def test_get_db_uses_config_path(client):
    with app.app_context():
        if hasattr(g, "_database"):
            del g._database

        # App config 'DATABASE' should be 'test_analysis.db' via the client fixture
        expected_path = app.config.get("DATABASE")

        # We can mock sqlite3.connect just to assert the path argument
        import unittest.mock as mock

        with mock.patch("app.sqlite3.connect") as mock_connect:
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

            with mock.patch("app.sqlite3.connect") as mock_connect:
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


def test_kerberoastable_route(client):
    app.before_request_funcs[None] = []

    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM hashes")

        # User 1: kerberoastable=1, enabled=1 (Should appear)
        c.execute(
            "INSERT INTO users (id, domain, username, original_domain, kerberoastable, enabled) VALUES (1, 'test_domain1', 'test_user1', 'test_orig1', 1, 1)"
        )
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (1, 0, 'cracked_pass1')")

        # User 2: kerberoastable=1, enabled=0 (Should NOT appear)
        c.execute(
            "INSERT INTO users (id, domain, username, original_domain, kerberoastable, enabled) VALUES (2, 'test_domain2', 'test_user2', 'test_orig2', 1, 0)"
        )
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (2, 0, 'cracked_pass2')")

        # User 3: kerberoastable=0, enabled=1 (Should NOT appear)
        c.execute(
            "INSERT INTO users (id, domain, username, original_domain, kerberoastable, enabled) VALUES (3, 'test_domain3', 'test_user3', 'test_orig3', 0, 1)"
        )
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (3, 0, 'cracked_pass3')")

        db.commit()

    response = client.get("/kerberoastable")

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


def test_asreproastable_route(client):
    app.before_request_funcs[None] = []

    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM hashes")

        # User 1: asreproastable=1, enabled=1 (Should appear)
        c.execute(
            "INSERT INTO users (id, domain, username, original_domain, asreproastable, enabled) VALUES (1, 'test_domain1', 'test_user1', 'test_orig1', 1, 1)"
        )
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (1, 0, 'cracked_pass1')")

        # User 2: asreproastable=1, enabled=0 (Should NOT appear)
        c.execute(
            "INSERT INTO users (id, domain, username, original_domain, asreproastable, enabled) VALUES (2, 'test_domain2', 'test_user2', 'test_orig2', 1, 0)"
        )
        c.execute("INSERT INTO hashes (user_id, is_history, cracked_password) VALUES (2, 0, 'cracked_pass2')")

        # User 3: asreproastable=0, enabled=1 (Should NOT appear)
        c.execute(
            "INSERT INTO users (id, domain, username, original_domain, asreproastable, enabled) VALUES (3, 'test_domain3', 'test_user3', 'test_orig3', 0, 1)"
        )
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


def test_logout(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1

    response = client.get("/logout")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"

    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_change_password_unauthenticated_redirect(client):
    response = client.get("/change_password")
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"


def test_change_password_get_authenticated(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
    response = client.get("/change_password")
    assert response.status_code == 200


def test_change_password_post_incorrect_current(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
    response = client.post(
        "/change_password",
        data={"current_password": "wrongpassword", "new_password": "newpassword123", "confirm_password": "newpassword123"},
        follow_redirects=True,
    )
    assert b"Incorrect current password" in response.data


def test_change_password_post_mismatch_new(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
    response = client.post(
        "/change_password",
        data={"current_password": "password123", "new_password": "newpassword123", "confirm_password": "newpassword456"},
        follow_redirects=True,
    )
    assert b"New passwords do not match" in response.data


def test_change_password_post_short_new(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1
    response = client.post(
        "/change_password",
        data={"current_password": "password123", "new_password": "short", "confirm_password": "short"},
        follow_redirects=True,
    )
    assert b"Password must be at least 8 characters long" in response.data


def test_change_password_post_success(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 1

    with client.application.app_context():
        db = get_db()
        db.execute("UPDATE web_users SET must_change_password = 1 WHERE id = 1")
        db.commit()

    response = client.post(
        "/change_password",
        data={"current_password": "password123", "new_password": "newpassword123", "confirm_password": "newpassword123"},
        follow_redirects=True,
    )

    with client.session_transaction() as sess:
        assert "Password changed successfully" in [msg[1] for msg in sess.get("_flashes", [])]

    # Since dashboard.html doesn't seem to render flash messages, we check if it redirected to the dashboard correctly
    assert response.status_code == 200
    assert b"Password Analysis Report" in response.data  # check if we are on dashboard

    with client.application.app_context():
        from werkzeug.security import check_password_hash

        user = query_db("SELECT * FROM web_users WHERE id = 1", one=True)
        assert user["must_change_password"] == 0
        assert check_password_hash(user["password_hash"], "newpassword123")


def test_export_reset_csv(client):
    # Setup test data
    with client.application.app_context():
        import app

        db = app.get_db()
        c = db.cursor()
        c.execute("INSERT INTO users (id, domain, username, enabled) VALUES (1, 'TEST', 'user1', 1)")
        c.execute("INSERT INTO users (id, domain, username, enabled) VALUES (2, 'TEST', 'user2', 1)")

        # User 1 has cracked password, User 2 has uncracked, User 1 history is cracked
        c.execute("INSERT INTO hashes (id, user_id, nt_hash, cracked_password, is_history) VALUES (1, 1, 'hash1', 'password123', 0)")
        c.execute("INSERT INTO hashes (id, user_id, nt_hash, cracked_password, is_history) VALUES (2, 2, 'hash2', NULL, 0)")
        c.execute("INSERT INTO hashes (id, user_id, nt_hash, cracked_password, is_history) VALUES (3, 1, 'hashold', 'oldpass', 1)")
        db.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = 1

    response = client.get("/export_reset_csv")
    assert response.status_code == 200
    assert response.headers["Content-disposition"] == "attachment; filename=accounts_needing_reset.csv"

    csv_data = response.data.decode("utf-8")
    assert "Domain,Username,Password,Password Length,Needs Reset\r\n" in csv_data
    assert "TEST,user1,password123,11,TRUE\r\n" in csv_data
    assert "TEST,user2" not in csv_data


def test_export_shared_csv(client):
    # Setup test data
    with client.application.app_context():
        import app

        db = app.get_db()
        c = db.cursor()
        c.execute("INSERT INTO users (id, domain, username, enabled) VALUES (1, 'TEST', 'user1', 1)")
        c.execute("INSERT INTO users (id, domain, username, enabled) VALUES (2, 'TEST', 'user2', 1)")
        c.execute("INSERT INTO users (id, domain, username, enabled) VALUES (3, 'TEST', 'user3', 1)")

        # User 1 & 2 share a cracked password
        c.execute("INSERT INTO hashes (id, user_id, nt_hash, cracked_password, is_history) VALUES (1, 1, 'hash1', 'password123', 0)")
        c.execute("INSERT INTO hashes (id, user_id, nt_hash, cracked_password, is_history) VALUES (2, 2, 'hash1', 'password123', 0)")

        # User 3 has an uncracked shared password (this is an edge case, usually shared passwords are cracked ones or known ones)
        # Actually shared_hashes table only stores cracked passwords or whatever was in hashes table.
        # Let's insert uncracked shared password
        c.execute("INSERT INTO hashes (id, user_id, nt_hash, cracked_password, is_history) VALUES (3, 3, 'hash2', NULL, 0)")

        c.execute(
            "INSERT INTO shared_hashes (nt_hash, cracked_password, count, shared_by) VALUES ('hash1', 'password123', 2, 'TEST\\user1, TEST\\user2')"
        )
        c.execute(
            "INSERT INTO shared_hashes (nt_hash, cracked_password, count, shared_by) VALUES ('hash2', NULL, 2, 'TEST\\user3, TEST\\user4')"
        )
        db.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = 1

    response = client.get("/export_shared_csv")
    assert response.status_code == 200
    assert response.headers["Content-disposition"] == "attachment; filename=shared_passwords.csv"

    csv_data = response.data.decode("utf-8")
    assert "Domain,Username,Password,Password Length,Reuse Count\r\n" in csv_data
    assert "TEST,user1,password123,11,2\r\n" in csv_data
    assert "TEST,user2,password123,11,2\r\n" in csv_data
    assert "TEST,user3,,0,2\r\n" in csv_data


def test_csv_injection_sanitization(client):
    with client.application.app_context():
        import app

        db = app.get_db()
        c = db.cursor()
        # Insert a user with a dangerous username
        c.execute(
            "INSERT INTO users (id, domain, username, enabled, passwordnotreqd, pwdneverexpires, kerberoastable, asreproastable) VALUES (100, 'TEST', '=cmd|'' /C calc''!A0', 1, 0, 0, 0, 0)"
        )
        c.execute("INSERT INTO hashes (id, user_id, nt_hash, cracked_password, is_history) VALUES (100, 100, 'hash100', '+12345', 0)")
        db.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = 100

    # Test export_csv
    response = client.get("/export_csv")
    assert response.status_code == 200
    csv_data = response.data.decode("utf-8")
    assert "'=cmd|' /C calc'!A0" in csv_data

    # Test export_reset_csv
    response = client.get("/export_reset_csv")
    assert response.status_code == 200
    csv_data = response.data.decode("utf-8")
    assert "'+12345" in csv_data


def test_export_length_csv(client):
    # Setup test data
    with client.application.app_context():
        import app

        db = app.get_db()
        c = db.cursor()
        c.execute("INSERT INTO users (id, domain, username, enabled) VALUES (1, 'TEST', 'user1', 1)")
        c.execute("INSERT INTO hashes (id, user_id, nt_hash, cracked_password, is_history) VALUES (1, 1, 'hash1', 'password123', 0)")
        c.execute("INSERT INTO policy_violations (user_id, policy_name, reason) VALUES (1, 'Test Policy', 'Length < 14')")
        db.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = 1

    response = client.get("/export_length_csv")
    assert response.status_code == 200
    assert response.headers["Content-disposition"] == "attachment; filename=length_violations.csv"

    csv_data = response.data.decode("utf-8")
    assert "Domain,Username,Actual Password Length,Length Violation,Requirement,Policy Name\r\n" in csv_data
    assert "TEST,user1,11,TRUE,< 14,Test Policy\r\n" in csv_data
