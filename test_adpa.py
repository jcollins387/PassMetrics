import json
import pytest
import os
import tempfile
from unittest.mock import patch

from adpa import parse_policy, parse_high_value

def test_parse_policy_none_or_empty():
    assert parse_policy(None) == {}
    assert parse_policy('') == {}

def test_parse_policy_valid_json():
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
        json.dump({"test": "data"}, tmp)
        tmp_path = tmp.name

    try:
        result = parse_policy(tmp_path)
        assert result == {"test": "data"}
    finally:
        os.remove(tmp_path)

def test_parse_policy_invalid_json():
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
        tmp.write("{invalid_json_here")
        tmp_path = tmp.name

    try:
        with patch('adpa.logging.error') as mock_log:
            result = parse_policy(tmp_path)
            assert result == {}
            mock_log.assert_called_once()
            args, _ = mock_log.call_args
            assert args[0].startswith("Failed to read policy file:")
    finally:
        os.remove(tmp_path)

def test_parse_policy_nonexistent_file():
    with patch('adpa.logging.error') as mock_log:
        result = parse_policy("this_file_does_not_exist_at_all.json")
        assert result == {}
        mock_log.assert_called_once()
        args, _ = mock_log.call_args
        assert args[0].startswith("Failed to read policy file:")

def test_parse_high_value_none_or_empty():
    assert parse_high_value(None) == ['Domain Admins', 'Enterprise Admins']
    assert parse_high_value('') == ['Domain Admins', 'Enterprise Admins']

def test_parse_high_value_valid_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
        # Include normal lines, lines with trailing/leading spaces, and empty lines
        tmp.write("Domain Admins\n")
        tmp.write("  Enterprise Admins  \n")
        tmp.write("\n")
        tmp.write("Custom Admin Group\n")
        tmp_path = tmp.name

    try:
        result = parse_high_value(tmp_path)
        assert result == ['Domain Admins', 'Enterprise Admins', 'Custom Admin Group']
    finally:
        os.remove(tmp_path)

def test_parse_high_value_nonexistent_file():
    with patch('adpa.logging.error') as mock_log:
        result = parse_high_value("this_file_does_not_exist_at_all.txt")
        assert result == ['Domain Admins', 'Enterprise Admins']
        mock_log.assert_called_once()
        args, _ = mock_log.call_args
        assert args[0].startswith("Failed to read high value file:")

def test_domain_mapping():
    import json
    import os
    import sqlite3
    from adpa import init_db, parse_ntds

    DB_PATH = "test_analysis.db"

    # Setup test NTDS mapping scenario
    ntds_data = """SHORT\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
corp.short.local\\user1:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SHORT\\user2:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
OTHER\\user3:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"""
    with open("test_mapping_ntds.txt", "w") as f:
        f.write(ntds_data)

    mapping_data = {
        "SHORT": ["short.local", "corp.short.local"],
        "OTHER": ["other.local", "corp.other.local"]
    }
    with open("test_mapping.json", "w") as f:
        json.dump(mapping_data, f)

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db(DB_PATH)

    # user1 exists as 'corp.short.local\user1', so 'SHORT\user1' should map to 'short.local\user1' due to elimination.
    # user2 has no other mapping found, so 'SHORT\user2' will default to 'short.local' (the first remaining option).
    # user3 'OTHER\user3' has no mappings found, so defaults to 'other.local'.
    parse_ntds("test_mapping_ntds.txt", DB_PATH, mapping_path="test_mapping.json", interactive=False)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT original_domain, domain, username FROM users ORDER BY username")
    users = c.fetchall()
    conn.close()

    # Create map to check expectations easily
    result = {(r[0].upper(), r[2].lower()): r[1].lower() for r in users}

    assert result[('SHORT', 'user1')] == 'short.local'
    assert result[('CORP.SHORT.LOCAL', 'user1')] == 'corp.short.local'
    assert result[('SHORT', 'user2')] == 'short.local'
    assert result[('OTHER', 'user3')] == 'other.local'

    os.remove("test_mapping_ntds.txt")
    os.remove("test_mapping.json")
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
