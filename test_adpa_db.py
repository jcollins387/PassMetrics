import sqlite3
import pytest
from adpa import init_db

def test_init_db_creates_tables_and_indexes(tmp_path):
    db_path = tmp_path / "test_schema.db"
    init_db(str(db_path))

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Verify tables
    expected_tables = {
        "users",
        "hashes",
        "cracked_hashes",
        "user_groups",
        "policy_violations",
        "config",
        "shared_hashes",
        "web_users",
    }

    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    created_tables = {row[0] for row in c.fetchall()}

    for table in expected_tables:
        assert table in created_tables, f"Table '{table}' was not created."

    # Verify indexes
    expected_indexes = {
        "idx_users_domain_username",
        "idx_users_flags",
        "idx_hashes_user_id",
        "idx_hashes_nt_hash",
        "idx_hashes_nt_hash_lower",
        "idx_hashes_is_history",
        "idx_hashes_history_cracked",
        "idx_user_groups_user_id"
    }

    c.execute("SELECT name FROM sqlite_master WHERE type='index'")
    created_indexes = {row[0] for row in c.fetchall()}

    for index in expected_indexes:
        assert index in created_indexes, f"Index '{index}' was not created."

    conn.close()

def test_init_db_idempotent(tmp_path):
    db_path = tmp_path / "test_schema.db"

    # Call twice
    init_db(str(db_path))
    init_db(str(db_path))

    # Should not raise an exception, and tables should still exist
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in c.fetchall()}
    assert "users" in tables
    conn.close()
