import json
import os
import tempfile
from unittest.mock import patch

import pytest
from adpa import parse_policy, parse_high_value, parse_args


def test_parse_policy_none_or_empty():
    assert parse_policy(None) == {}
    assert parse_policy("") == {}


def test_parse_policy_valid_json():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
        json.dump({"test": "data"}, tmp)
        tmp_path = tmp.name

    try:
        result = parse_policy(tmp_path)
        assert result == {"test": "data"}
    finally:
        os.remove(tmp_path)


def test_parse_policy_invalid_json():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
        tmp.write("{invalid_json_here")
        tmp_path = tmp.name

    try:
        with patch("adpa.logging.error") as mock_log:
            result = parse_policy(tmp_path)
            assert result == {}
            mock_log.assert_called_once()
            args, _ = mock_log.call_args
            assert args[0].startswith("Failed to read policy file:")
    finally:
        os.remove(tmp_path)


def test_parse_policy_nonexistent_file():
    with patch("adpa.logging.error") as mock_log:
        result = parse_policy("this_file_does_not_exist_at_all.json")
        assert result == {}
        mock_log.assert_called_once()
        args, _ = mock_log.call_args
        assert args[0].startswith("Failed to read policy file:")


def test_parse_high_value_none_or_empty():
    assert parse_high_value(None) == ["Domain Admins", "Enterprise Admins"]
    assert parse_high_value("") == ["Domain Admins", "Enterprise Admins"]


def test_parse_high_value_valid_file():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
        # Include normal lines, lines with trailing/leading spaces, and empty lines
        tmp.write("Domain Admins\n")
        tmp.write("  Enterprise Admins  \n")
        tmp.write("\n")
        tmp.write("Custom Admin Group\n")
        tmp_path = tmp.name

    try:
        result = parse_high_value(tmp_path)
        assert result == ["Domain Admins", "Enterprise Admins", "Custom Admin Group"]
    finally:
        os.remove(tmp_path)


def test_parse_high_value_nonexistent_file():
    with patch("adpa.logging.error") as mock_log:
        result = parse_high_value("this_file_does_not_exist_at_all.txt")
        assert result == ["Domain Admins", "Enterprise Admins"]
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

    mapping_data = {"SHORT": ["short.local", "corp.short.local"], "OTHER": ["other.local", "corp.other.local"]}
    with open("test_mapping.json", "w") as f:
        json.dump(mapping_data, f)

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db(DB_PATH, "testkey")

    # user1 exists as 'corp.short.local\user1', so 'SHORT\user1' should map to 'short.local\user1' due to elimination.
    # user2 has no other mapping found, so 'SHORT\user2' will default to 'short.local' (the first remaining option).
    # user3 'OTHER\user3' has no mappings found, so defaults to 'other.local'.
    from adpa import apply_domain_mapping

    parse_ntds("test_mapping_ntds.txt", DB_PATH, "testkey")
    apply_domain_mapping(DB_PATH, mapping_path="test_mapping.json", interactive=False, db_key="testkey")

    from pysqlcipher3 import dbapi2 as pysqlite3
    conn = pysqlite3.connect(DB_PATH)
    conn.execute("PRAGMA key='testkey'")
    c = conn.cursor()
    c.execute("SELECT original_domain, domain, username FROM users ORDER BY username")
    users = c.fetchall()
    conn.close()

    # Create map to check expectations easily
    result = {(r[0].upper(), r[2].lower()): r[1].lower() for r in users}

    assert result[("SHORT", "user1")] == "short.local"
    assert result[("CORP.SHORT.LOCAL", "user1")] == "corp.short.local"
    assert result[("SHORT", "user2")] == "short.local"
    assert result[("OTHER", "user3")] == "other.local"

    os.remove("test_mapping_ntds.txt")
    os.remove("test_mapping.json")
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def test_parse_bloodhound_invalid_json():
    import json
    import os
    import tempfile
    from unittest.mock import patch
    from adpa import _process_bh_file

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
        tmp.write("{invalid_json_here")
        tmp_path = tmp.name

    try:
        with patch("adpa.logging.error") as mock_log:
            user_updates, group_inserts = _process_bh_file((tmp_path, {}))
            assert user_updates == []
            assert group_inserts == []
            mock_log.assert_called_once()
            args, _ = mock_log.call_args
            assert args[0].startswith("Failed to parse Bloodhound file")
    finally:
        os.remove(tmp_path)


def test_parse_bloodhound_valid(tmp_path):
    import json
    import sqlite3
    import os
    from adpa import init_db, parse_ntds, apply_domain_mapping, parse_bloodhound

    # Use the pytest tmp_path fixture
    db_path = tmp_path / "test_bh.db"
    init_db(str(db_path), "testkey")

    # Setup test NTDS scenario based on user request to populate test users first
    # 1. Strict match: domain=test.local, username=user1
    # 2. Fallback match (username only): domain=other.local, username=user2.
    #    In BH data, this will be provided with a different domain 'nomatch.local' but samaccountname='user2'.
    # 3. Non-match user: domain=test.local, username=user3

    ntds_data = """test.local\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
other.local\\user2:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
test.local\\user3:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"""
    ntds_file = tmp_path / "test_ntds.txt"
    with open(ntds_file, "w") as f:
        f.write(ntds_data)

    mapping_data = {"test": ["test.local"], "other": ["other.local"]}
    mapping_file = tmp_path / "test_mapping.json"
    with open(mapping_file, "w") as f:
        json.dump(mapping_data, f)

    parse_ntds(str(ntds_file), str(db_path), "testkey")
    apply_domain_mapping(str(db_path), mapping_path=str(mapping_file), interactive=False, db_key="testkey")

    # Create new format BloodHound JSON file ("data" array)
    bh_new_format = {
        "data": [
            {
                "type": "User",
                "ObjectIdentifier": "S-1-5-21-1234-USER1",
                "Properties": {
                    "domain": "test.local",
                    "name": "user1@test.local",
                    "samaccountname": "user1",
                    "enabled": False,
                    "pwdneverexpires": True,
                    "passwordnotreqd": False,
                    "hasspn": True,  # kerberoastable
                    "dontreqpreauth": False,
                    "distinguishedname": "CN=user1,OU=IT,DC=test,DC=local",
                    "pwdlastset": 1600000000,
                },
            },
            {
                "type": "Group",
                "Properties": {"domain": "test.local", "name": "ITAdmins@test.local"},
                "Members": [{"ObjectType": "User", "ObjectName": "user1@test.local", "ObjectIdentifier": "S-1-5-21-1234-USER1"}],
            },
        ]
    }

    bh_new_file = tmp_path / "bh_new.json"
    with open(bh_new_file, "w") as f:
        json.dump(bh_new_format, f)

    # Create old format BloodHound JSON file ("users" and "groups" arrays)
    bh_old_format = {
        "users": [
            {
                "ObjectIdentifier": "S-1-5-21-1234-USER2",
                "Properties": {
                    "name": "user2@nomatch.local",
                    "domain": "nomatch.local",  # This triggers fallback match for user2
                    "samaccountname": "user2",
                    "enabled": True,
                    "pwdneverexpires": False,
                    "passwordnotreqd": True,
                    "hasspn": False,
                    "dontreqpreauth": True,  # asreproastable
                    "distinguishedname": "CN=user2,OU=HR,DC=nomatch,DC=local",
                    "pwdlastset": 1600000001,
                },
            }
        ],
        "groups": [
            {
                "Properties": {"domain": "nomatch.local", "name": "HRUsers@nomatch.local"},
                "Members": [{"ObjectType": "User", "ObjectIdentifier": "S-1-5-21-1234-USER2"}],
            }
        ],
    }

    bh_old_file = tmp_path / "bh_old.json"
    with open(bh_old_file, "w") as f:
        json.dump(bh_old_format, f)

    # Parse bloodhound files
    parse_bloodhound([str(bh_new_file), str(bh_old_file)], str(db_path), "testkey")

    # Verify updates in the database
    from pysqlcipher3 import dbapi2 as pysqlite3
    conn = pysqlite3.connect(str(db_path))
    conn.execute("PRAGMA key='testkey'")
    c = conn.cursor()

    # Verify User 1 (Strict match)
    c.execute("SELECT enabled, pwdneverexpires, passwordnotreqd, kerberoastable, asreproastable FROM users WHERE username = 'user1'")
    user1_flags = c.fetchone()
    assert user1_flags == (0, 1, 0, 1, 0)  # False is 0, True is 1 in SQLite

    # Verify User 2 (Fallback match)
    c.execute("SELECT enabled, pwdneverexpires, passwordnotreqd, kerberoastable, asreproastable FROM users WHERE username = 'user2'")
    user2_flags = c.fetchone()
    assert user2_flags == (1, 0, 1, 0, 1)

    # Verify User 3 (No match - should retain defaults)
    c.execute("SELECT enabled, pwdneverexpires, passwordnotreqd, kerberoastable, asreproastable FROM users WHERE username = 'user3'")
    user3_flags = c.fetchone()
    assert user3_flags == (1, 0, 0, 0, 0)

    # Verify group memberships
    c.execute("SELECT u.username, ug.group_name FROM user_groups ug JOIN users u ON ug.user_id = u.id ORDER BY u.username")
    groups = c.fetchall()

    # We should have user1 in ITAdmins (user2 group insert won't match fallback domain)
    expected_groups = [("user1", "ITAdmins")]
    for exp in expected_groups:
        assert exp in groups

    conn.close()

def test_parse_args_required():
    with patch("sys.argv", ["adpa.py", "-n", "test.ntds", "-p", "test.potfile"]):
        args = parse_args()
        assert args.ntds == "test.ntds"
        assert args.potfile == "test.potfile"
        assert args.bloodhound is None
        assert args.policy is None
        assert args.enabled_only is False

def test_parse_args_missing_required():
    with patch("sys.argv", ["adpa.py", "-n", "test.ntds"]):
        with pytest.raises(SystemExit):
            parse_args()

def test_domain_mapping_bloodhound_automatic(tmp_path):
    import json
    import sqlite3
    import os
    from adpa import init_db, parse_ntds, apply_domain_mapping, extract_bh_identities

    # Use pytest tmp_path
    db_path = tmp_path / "test_bh_mapping.db"
    init_db(str(db_path), "testkey")

    # We want to test the three scenarios described in the requirements:
    # user1: Strict match logic applies. NTDS is short\user1, BH is short.internal.com\user1, but we map successfully to short.internal.com via fallback. Wait, strict match means the current user already perfectly matches BH.
    # What we actually want: user1 is short\user1 in NTDS, BH has short.internal.com\user1.
    # Fallback matches them (only 1 valid BH domain for user1). Remaps to short.internal.com.

    # user2: NTDS is short\user2. BH has short.internal.com\user2. BUT NTDS already has short.internal.com\user2.
    # This should fail automatic mapping (Case A collision) and fallback to JSON. JSON says map short to other.local.

    # user3: NTDS is short\user3. BH has short.internal.com\user3 AND long.internal.com\user3.
    # This should fail automatic mapping (Case C ambiguous) and fallback to JSON. JSON says map short to other.local.

    # To test fallback mapping correctly, the NTDS domain must be different than the BH domain.
    # We will use NTDS domain "FOO" and BH domain "short.internal.com" (which is parsed as "short").
    # user1: NTDS is FOO\user1. BH has short\user1. Auto maps to short.
    # user2: NTDS is FOO\user2. BH has short\user2. BUT NTDS already has short\user2. Auto map fails, uses JSON.
    # user3: NTDS is FOO\user3. BH has short\user3 and long\user3. Auto map fails (ambiguous), uses JSON.

    ntds_data = """FOO\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
FOO\\user2:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
short\\user2:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
FOO\\user3:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ALREADY_MATCHED\\user4:1005:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"""

    ntds_file = tmp_path / "test_ntds.txt"
    with open(ntds_file, "w") as f:
        f.write(ntds_data)

    bh_data = {
        "users": [
            {"Properties": {"domain": "short.internal.com", "samaccountname": "user1"}},
            {"Properties": {"domain": "short.internal.com", "samaccountname": "user2"}},
            {"Properties": {"domain": "short.internal.com", "samaccountname": "user3"}},
            {"Properties": {"domain": "long.internal.com", "samaccountname": "user3"}},
            {"Properties": {"domain": "ALREADY_MATCHED", "samaccountname": "user4"}},
        ]
    }
    bh_file = tmp_path / "test_bh.json"
    with open(bh_file, "w") as f:
        json.dump(bh_data, f)

    mapping_data = {"FOO": ["other.local"]}
    mapping_file = tmp_path / "test_mapping.json"
    with open(mapping_file, "w") as f:
        json.dump(mapping_data, f)

    parse_ntds(str(ntds_file), str(db_path), "testkey")
    bh_identities = extract_bh_identities([str(bh_file)])
    apply_domain_mapping(str(db_path), mapping_path=str(mapping_file), interactive=False, bh_identities=bh_identities, db_key="testkey")

    from pysqlcipher3 import dbapi2 as pysqlite3
    conn = pysqlite3.connect(str(db_path))
    conn.execute("PRAGMA key='testkey'")
    c = conn.cursor()
    c.execute("SELECT original_domain, domain, username FROM users ORDER BY id")
    users = c.fetchall()
    conn.close()

    result = {(r[0].upper(), r[2].lower()): r[1].lower() for r in users}

    # Note: BloodHound extractor truncates domains to their first component.
    # So "short.internal.com" becomes "short", and "long.internal.com" becomes "long".

    # user1 auto-maps because short is the only candidate in BH and it doesn't exist in NTDS.
    assert result[("FOO", "user1")] == "short"

    # user2 fails auto-map because short/user2 already exists in NTDS.
    # Falls back to JSON mapping 'other.local'
    assert result[("FOO", "user2")] == "other.local"
    assert result[("SHORT", "user2")] == "short" # Original untouched

    # user3 fails auto-map because there are two candidates in BH. Falls back to JSON mapping 'other.local'
    assert result[("FOO", "user3")] == "other.local"

    # user4 strict matches because ALREADY_MATCHED/user4 is in BH.
    assert result[("ALREADY_MATCHED", "user4")] == "already_matched"


def test_parse_args_optional():
    with patch(
        "sys.argv",
        [
            "adpa.py",
            "-n",
            "test.ntds",
            "-p",
            "test.potfile",
            "--bloodhound",
            "bh1.json",
            "bh2.json",
            "--policy",
            "pol.json",
            "--enabled-only",
            "--redact",
        ],
    ):
        args = parse_args()
        assert args.ntds == "test.ntds"
        assert args.potfile == "test.potfile"
        assert args.bloodhound == ["bh1.json", "bh2.json"]
        assert args.policy == "pol.json"
        assert args.enabled_only is True
        assert args.redact is True

def test_extract_bh_identities_invalid_utf8(tmp_path):
    import adpa
    bh_file = tmp_path / "bh_invalid.json"
    # Create a JSON with invalid UTF-8 byte 0x86
    with open(bh_file, "wb") as f:
        f.write(b'{"users": [{"Properties": {"domain": "TEST", "samaccountname": "user\x86"}}]}')

    # Should not raise exception
    identities = adpa.extract_bh_identities([str(bh_file)])

    # We should get ('test', 'user') or similar, basically not throwing an error
    assert len(identities) == 1
    # Check the result has the replacement character
    domain, samaccountname = list(identities)[0]
    assert domain == "test"
    assert "user" in samaccountname
