import argparse
import json
import logging
from pysqlcipher3 import dbapi2 as sqlite3
import time
import re
import concurrent.futures
import secrets
import string
import os
import sys
import getpass
import stat
from werkzeug.security import generate_password_hash
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def init_db(db_path: str, db_key: str):
    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            username TEXT,
            original_domain TEXT,
            rid INTEGER,
            enabled BOOLEAN DEFAULT 1,
            pwdneverexpires BOOLEAN DEFAULT 0,
            passwordnotreqd BOOLEAN DEFAULT 0,
            kerberoastable BOOLEAN DEFAULT 0,
            asreproastable BOOLEAN DEFAULT 0,
            distinguishedname TEXT,
            pwdlastset INTEGER
        );
        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            lm_hash TEXT,
            nt_hash TEXT,
            is_history BOOLEAN,
            cracked_password TEXT,
            redacted_password TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS cracked_hashes (
            nt_hash TEXT PRIMARY KEY,
            cracked_password TEXT
        );
        CREATE TABLE IF NOT EXISTS user_groups (
            user_id INTEGER,
            group_name TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS policy_violations (
            user_id INTEGER,
            policy_name TEXT,
            reason TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS shared_hashes (
            nt_hash TEXT PRIMARY KEY,
            cracked_password TEXT,
            count INTEGER,
            shared_by TEXT
        );
        CREATE TABLE IF NOT EXISTS web_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            must_change_password BOOLEAN DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_users_domain_username ON users(domain, username);
        CREATE INDEX IF NOT EXISTS idx_users_flags ON users(enabled, kerberoastable, asreproastable);
        CREATE INDEX IF NOT EXISTS idx_hashes_user_id ON hashes(user_id);
        CREATE INDEX IF NOT EXISTS idx_hashes_nt_hash ON hashes(nt_hash);
        CREATE INDEX IF NOT EXISTS idx_hashes_nt_hash_lower ON hashes(lower(nt_hash));
        CREATE INDEX IF NOT EXISTS idx_hashes_is_history ON hashes(is_history);
        CREATE INDEX IF NOT EXISTS idx_hashes_history_cracked ON hashes(is_history, cracked_password);
        CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups(user_id);
    """)
    conn.commit()
    conn.close()


def parse_args():
    description = (
        "Analyze NTDS hashes against a potfile and optional Bloodhound data.\n\n"
        "Administrator Credentials:\n"
        "  On first run, the tool creates an 'Administrator' account for the web portal.\n"
        "  If running interactively, you will be prompted to set the password.\n"
        "  If running non-interactively, a secure random password is generated and saved\n"
        "  to 'admin_credentials.txt' with strict permissions."
    )
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    required = parser.add_argument_group("Required Arguments")
    required.add_argument("-n", "--ntds", required=True, help="NTDS file containing password hashes")
    required.add_argument(
        "-p",
        "--potfile",
        required=True,
        help="Hashcat potfile containing the cracked hashes",
    )

    optional = parser.add_argument_group("Optional Arguments")
    optional.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="Show this help message and exit",
    )
    optional.add_argument(
        "-b",
        "--bloodhound",
        nargs="+",
        help="One or more json files generated from bloodhound",
    )
    optional.add_argument("--policy", help="JSON file containing password policy")
    optional.add_argument("--high-value", help="File containing high value groups/OUs")
    optional.add_argument(
        "--enabled-only",
        action="store_true",
        help="Show only 'enabled' users (requires BloodHound data)",
    )
    optional.add_argument(
        "--redact",
        action="store_true",
        help="Redact the passwords and hashes in reports",
    )
    optional.add_argument(
        "--outdir",
        help="Directory to output HTML reports to. Defaults to report_<timestamp>",
    )
    optional.add_argument(
        "--domain-mapping",
        help="JSON file containing 1-to-many domain mappings from NTDS to BloodHound names",
    )
    optional.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt user for ambiguous domain mappings (requires --domain-mapping)",
    )

    return parser.parse_args()


def parse_potfile(potfile_path: str, db_path: str, db_key: str):
    """Parses hashcat potfile and inserts hashes into the DB."""
    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
    c = conn.cursor()
    batch = []

    with open(potfile_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Hashcat potfile format is hash:password
            parts = line.split(":", 1)
            if len(parts) == 2:
                # NTHashes in potfile are usually 32 chars long. We index by lowercase to avoid case issues
                h, p = parts
                if len(h) == 32:
                    if p.startswith("$HEX[") and p.endswith("]"):
                        try:
                            p = bytes.fromhex(p[5:-1]).decode("utf-8", errors="replace")
                        except ValueError:
                            pass
                    batch.append((h.lower(), p))

            if len(batch) >= 100000:
                c.executemany(
                    "INSERT OR IGNORE INTO cracked_hashes (nt_hash, cracked_password) VALUES (?, ?)",
                    batch,
                )
                batch = []

    if batch:
        c.executemany(
            "INSERT OR IGNORE INTO cracked_hashes (nt_hash, cracked_password) VALUES (?, ?)",
            batch,
        )

    conn.commit()
    conn.close()


def parse_ntds(ntds_path: str, db_path: str, db_key: str):
    """Parses NTDS dump, skips krbtgt/machine accounts, inserts directly into DB."""
    logging.info(f"Parsing NTDS file: {ntds_path}")

    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
    c = conn.cursor()

    # We use a temporary table to hold all parsed accounts before finalizing mappings
    c.executescript("""
        CREATE TEMP TABLE ntds_temp (
            id INTEGER PRIMARY KEY,
            original_domain TEXT,
            username TEXT,
            rid INTEGER,
            lm_hash TEXT,
            nt_hash TEXT,
            is_history BOOLEAN
        );
    """)

    temp_batch = []
    next_user_id = 1
    count = 0

    with open(ntds_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            count += 1
            if count % 100000 == 0:
                logging.info(f"Processed {count} lines from NTDS...")

            line = line.strip()
            if not line:
                continue

            # Expected format (e.g. impacket-secretsdump):
            # domain\username:RID:lmhash:nthash:::
            parts = line.split(":")
            if len(parts) < 4:
                continue

            domain_user = parts[0]
            if "\\" in domain_user:
                domain, username = domain_user.split("\\", 1)
            else:
                domain, username = "UNKNOWN", domain_user

            try:
                rid = int(parts[1])
            except ValueError:
                continue

            lm_hash = parts[2]
            nt_hash = parts[3]

            is_history = False
            base_username = username
            history_match = re.search(r"_history\d*$", username, re.IGNORECASE)
            if history_match:
                base_username = username[: history_match.start()]
                is_history = True

            if base_username.lower() == "krbtgt" or base_username.endswith("$"):
                continue

            temp_batch.append((next_user_id, domain, base_username, rid, lm_hash, nt_hash, is_history))
            next_user_id += 1

            if len(temp_batch) >= 100000:
                c.executemany(
                    "INSERT INTO ntds_temp (id, original_domain, username, rid, lm_hash, nt_hash, is_history) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    temp_batch,
                )
                temp_batch = []

    if temp_batch:
        c.executemany(
            "INSERT INTO ntds_temp (id, original_domain, username, rid, lm_hash, nt_hash, is_history) VALUES (?, ?, ?, ?, ?, ?, ?)",
            temp_batch,
        )

    conn.commit()

    logging.info("Resolving domain mappings...")
    c.execute("CREATE INDEX idx_ntds_temp_dom_user ON ntds_temp(original_domain, username)")

    # Process unique original_domain/username combinations to determine final domain
    c.execute("SELECT original_domain, username, MIN(rid) FROM ntds_temp GROUP BY original_domain, username")
    unique_users = c.fetchall()

    users_batch = []
    user_key_to_id = {}
    next_final_id = 1
    orig_to_final_id = {}

    for row in unique_users:
        orig_domain = row[0]
        base_username = row[1]
        rid = row[2] if row[2] is not None else 0
        final_domain = orig_domain  # Domain is original domain initially

        key = f"{final_domain}\\{base_username}".lower()
        if key not in user_key_to_id:
            user_key_to_id[key] = next_final_id
            users_batch.append((next_final_id, final_domain, base_username, orig_domain, rid))
            next_final_id += 1

        orig_to_final_id[f"{orig_domain}\\{base_username}".lower()] = user_key_to_id[key]

    # Insert into real users table
    batch_size = 100000
    for i in range(0, len(users_batch), batch_size):
        c.executemany(
            "INSERT INTO users (id, domain, username, original_domain, rid) VALUES (?, ?, ?, ?, ?)",
            users_batch[i : i + batch_size],
        )

    # Now we need to map the temp hashes to the final user_ids
    logging.info("Migrating hashes from temp to final tables...")

    hashes_batch = []
    c.execute("SELECT original_domain, username, lm_hash, nt_hash, is_history FROM ntds_temp")
    for h_row in c.fetchall():
        orig_domain, username, lm_hash, nt_hash, is_history = h_row
        orig_key = f"{orig_domain}\\{username}".lower()
        final_id = orig_to_final_id.get(orig_key)
        if final_id:
            hashes_batch.append((final_id, lm_hash, nt_hash, is_history))

        if len(hashes_batch) >= 100000:
            c.executemany(
                "INSERT INTO hashes (user_id, lm_hash, nt_hash, is_history) VALUES (?, ?, ?, ?)",
                hashes_batch,
            )
            hashes_batch = []

    if hashes_batch:
        c.executemany(
            "INSERT INTO hashes (user_id, lm_hash, nt_hash, is_history) VALUES (?, ?, ?, ?)",
            hashes_batch,
        )

    c.execute("DROP TABLE ntds_temp")
    conn.commit()

    logging.info("Updating hashes with cracked passwords...")
    # Link cracked passwords to the hashes
    c.execute("""
        UPDATE hashes
        SET cracked_password = (
            SELECT cracked_password
            FROM cracked_hashes
            WHERE cracked_hashes.nt_hash = lower(hashes.nt_hash)
        )
        WHERE lower(hashes.nt_hash) IN (SELECT nt_hash FROM cracked_hashes)
    """)
    conn.commit()
    conn.close()


def extract_bh_identities(bh_files: List[str]) -> set:
    """Extracts a set of all unique (domain, username) combinations from Bloodhound files."""
    identities = set()
    for bh_file in bh_files:
        with open(bh_file, "r", encoding="utf-8", errors="replace") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                continue

            data_list = []
            if "data" in data:
                data_list = data["data"]
            elif "users" in data:
                data_list = data["users"]
            else:
                if isinstance(data, list):
                    data_list = data

            for item in data_list:
                item_type = item.get("type", item.get("Type", "")).upper()
                props = item.get("Properties", {})

                if item_type == "USER" or (not item_type and props.get("samaccountname")):
                    domain = props.get("domain", "")
                    if domain:
                        domain = domain.split(".")[0].lower()
                    samaccountname = props.get("samaccountname", "")
                    if samaccountname:
                        samaccountname = samaccountname.lower()
                    if domain and samaccountname:
                        identities.add((domain, samaccountname))
    return identities


def _build_identifier_map(bh_files: List[str]) -> Dict[str, str]:
    identifier_map = {}
    for bh_file in bh_files:
        with open(bh_file, "r", encoding="utf-8", errors="replace") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                continue

            data_list = []
            if "data" in data:
                data_list = data["data"]
            elif "users" in data:
                data_list = data["users"]
            elif "groups" in data:
                data_list = data["groups"]
            else:
                if isinstance(data, list):
                    data_list = data

            for item in data_list:
                props = item.get("Properties", {})
                obj_id = item.get("ObjectIdentifier")
                name = props.get("name")
                if obj_id and name:
                    identifier_map[obj_id] = name
    return identifier_map


def _process_bh_file(args):
    bh_file, global_identifier_map = args
    user_updates = []
    group_inserts = []

    with open(bh_file, "r", encoding="utf-8", errors="replace") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            logging.error(f"Failed to parse Bloodhound file {bh_file}")
            return user_updates, group_inserts

        data_list = []
        if "data" in data:
            data_list = data["data"]
        elif "users" in data:
            data_list = data["users"]
            for item in data_list:
                item["type"] = "User"
        elif "groups" in data:
            data_list = data["groups"]
            for item in data_list:
                item["type"] = "Group"
        else:
            if isinstance(data, list):
                data_list = data
            else:
                return user_updates, group_inserts

        for item in data_list:
            item_type = item.get("type", item.get("Type", "")).upper()
            props = item.get("Properties", {})

            if item_type == "USER" or (not item_type and props.get("samaccountname")):
                domain = props.get("domain", "").split(".")[0]
                samaccountname = props.get("samaccountname", "")
                if samaccountname:
                    user_updates.append(
                        {
                            "domain": domain.lower(),
                            "samaccountname": samaccountname.lower(),
                            "enabled": props.get("enabled", True),
                            "pwdneverexpires": props.get("pwdneverexpires", False),
                            "passwordnotreqd": props.get("passwordnotreqd", False),
                            "kerberoastable": props.get("hasspn", False),
                            "asreproastable": props.get("dontreqpreauth", False),
                            "distinguishedname": props.get("distinguishedname", ""),
                            "pwdlastset": props.get("pwdlastset", 0),
                        }
                    )

            if item_type == "GROUP" or (not item_type and "Members" in item):
                group_name = props.get("name", "").split("@")[0] if props.get("name") else ""
                if group_name:
                    for member in item.get("Members", []):
                        m_type = member.get("ObjectType", member.get("type", "")).upper()
                        if m_type == "USER":
                            m_name = member.get("ObjectName", member.get("name", ""))
                            if not m_name and member.get("ObjectIdentifier"):
                                m_name = global_identifier_map.get(member.get("ObjectIdentifier"), "")
                            if m_name:
                                m_parts = m_name.split("@")
                                m_user = m_parts[0].lower()
                                m_dom = m_parts[1].split(".")[0].lower() if len(m_parts) > 1 else ""
                                group_inserts.append((m_dom, m_user, group_name))

    return user_updates, group_inserts


def parse_bloodhound(bh_files: List[str], db_path: str, db_key: str):
    """Parses bloodhound users JSON and group memberships using multiprocessing."""
    if not bh_files:
        return

    logging.info(f"Parsing {len(bh_files)} Bloodhound files...")
    all_user_updates = []
    all_group_inserts = []

    # Pass 1: Build a global identifier map
    global_identifier_map = _build_identifier_map(bh_files)

    # Pass 2: Extract data
    args_list = [(f, global_identifier_map) for f in bh_files]
    with concurrent.futures.ProcessPoolExecutor() as executor:
        for updates, inserts in executor.map(_process_bh_file, args_list):
            all_user_updates.extend(updates)
            all_group_inserts.extend(inserts)

    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
    c = conn.cursor()

    # Batch update users
    if all_user_updates:
        logging.info("Applying Bloodhound user updates to DB...")
        # Since sqlite doesn't easily support updating a join or doing an executemany with fallback directly without a temp table,
        # we will use a temporary table to hold updates, and then apply them.
        c.executescript("""
            CREATE TEMP TABLE bh_users (
                domain TEXT,
                username TEXT,
                enabled BOOLEAN,
                pwdneverexpires BOOLEAN,
                passwordnotreqd BOOLEAN,
                kerberoastable BOOLEAN,
                asreproastable BOOLEAN,
                distinguishedname TEXT,
                pwdlastset INTEGER
            );
            CREATE INDEX idx_bh_users ON bh_users(domain, username);
            CREATE INDEX idx_bh_users_username ON bh_users(username);
        """)

        batch = [
            (
                u["domain"],
                u["samaccountname"],
                u["enabled"],
                u["pwdneverexpires"],
                u["passwordnotreqd"],
                u["kerberoastable"],
                u["asreproastable"],
                u["distinguishedname"],
                u["pwdlastset"],
            )
            for u in all_user_updates
        ]
        c.executemany("INSERT INTO bh_users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", batch)

        # Apply strict match (domain + username)
        c.execute("""
            UPDATE users SET
                enabled = bh_users.enabled,
                pwdneverexpires = bh_users.pwdneverexpires,
                passwordnotreqd = bh_users.passwordnotreqd,
                kerberoastable = bh_users.kerberoastable,
                asreproastable = bh_users.asreproastable,
                distinguishedname = bh_users.distinguishedname,
                pwdlastset = bh_users.pwdlastset
            FROM bh_users
            WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)
        """)

        # Apply fallback match (username only for users that weren't matched above)
        # This mirrors the fallback_index logic in the original script
        c.execute("""
            UPDATE users SET
                enabled = bh_users.enabled,
                pwdneverexpires = bh_users.pwdneverexpires,
                passwordnotreqd = bh_users.passwordnotreqd,
                kerberoastable = bh_users.kerberoastable,
                asreproastable = bh_users.asreproastable,
                distinguishedname = bh_users.distinguishedname,
                pwdlastset = bh_users.pwdlastset
            FROM bh_users
            WHERE bh_users.username = lower(users.username)
              AND NOT EXISTS (
                  SELECT 1 FROM bh_users bh2 WHERE bh2.domain = lower(users.domain) AND bh2.username = lower(users.username)
              )
        """)

        c.execute("DROP TABLE bh_users")

    if all_group_inserts:
        logging.info("Applying Bloodhound group memberships to DB...")
        c.executescript("""
            CREATE TEMP TABLE bh_groups (
                domain TEXT,
                username TEXT,
                group_name TEXT
            );
            CREATE INDEX idx_bh_groups ON bh_groups(domain, username);
            CREATE INDEX idx_bh_groups_username ON bh_groups(username);
        """)

        c.executemany("INSERT INTO bh_groups VALUES (?, ?, ?)", all_group_inserts)

        # Strict match insert
        c.execute("""
            INSERT INTO user_groups (user_id, group_name)
            SELECT u.id, g.group_name
            FROM users u
            JOIN bh_groups g ON lower(u.domain) = g.domain AND lower(u.username) = g.username
        """)

        # Fallback match insert for those not matched strictly
        c.execute("""
            INSERT INTO user_groups (user_id, group_name)
            SELECT u.id, g.group_name
            FROM users u
            JOIN bh_groups g ON lower(u.username) = g.username
            WHERE NOT EXISTS (
                SELECT 1 FROM bh_groups bg WHERE bg.domain = lower(u.domain) AND bg.username = lower(u.username)
            )
        """)

        c.execute("DROP TABLE bh_groups")

    conn.commit()
    conn.close()


def parse_high_value(file_path: Optional[str]) -> List[str]:
    """Returns list of high value groups."""
    if not file_path:
        return ["Domain Admins", "Enterprise Admins"]

    groups = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                val = line.strip()
                if val:
                    groups.append(val)
        return groups
    except Exception as e:
        logging.error(f"Failed to read high value file: {e}")
        return ["Domain Admins", "Enterprise Admins"]


def parse_policy(file_path: Optional[str]) -> Dict:
    """Returns policy dict."""
    if not file_path:
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to read policy file: {e}")
        return {}


def calculate_metrics(db_path: str, policy: Dict, redact: bool, enabled_only: bool, db_key: str):
    logging.info("Calculating policy violations and database setup...")
    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
    c = conn.cursor()

    enabled_filter = "AND u.enabled = 1" if enabled_only else ""

    # Redact cracked passwords directly in the cracked_password column
    if redact:
        logging.info("Redacting passwords in DB...")
        c.execute("""
            UPDATE hashes
            SET cracked_password = CASE
                WHEN length(cracked_password) <= 2 THEN substr('********************************', 1, length(cracked_password))
                ELSE substr(cracked_password, 1, 1) || substr('********************************', 1, length(cracked_password)-2) || substr(cracked_password, -1, 1)
            END
            WHERE cracked_password IS NOT NULL
        """)
        conn.commit()

    # Policy Violations
    logging.info("Calculating policy violations...")
    c.execute(f"""
        SELECT u.id, h.cracked_password, group_concat(lower(ug.group_name)), u.distinguishedname, u.pwdlastset, u.username
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        LEFT JOIN user_groups ug ON u.id = ug.user_id
        WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL {enabled_filter}
        GROUP BY u.id
    """)

    violations = []
    fgpp_policies = policy.get("fgpp", {})
    base_policy = policy.get("base", {})

    current_time = time.time()

    # Pre-process FGPP policies
    processed_fgpp = []
    for policy_key, g_policy in fgpp_policies.items():
        processed_fgpp.append(
            {
                "policy": g_policy,
                "match_groups": set(g.lower() for g in g_policy.get("match_groups", [])),
                "match_ous": [ou.lower() for ou in g_policy.get("match_ous", [])],
                "match_usernames": [re.compile(regex, re.IGNORECASE) for regex in g_policy.get("match_usernames", [])],
            }
        )

    for row in c.fetchall():
        user_id = row[0]
        pwd = row[1]
        user_groups_lower = set(row[2].split(",")) if row[2] else set()
        dn_lower = row[3].lower() if row[3] else ""
        pwdlastset = row[4]
        username = row[5] or ""

        matched_policies = []
        for p in processed_fgpp:
            matched = False

            # Check groups
            for g in p["match_groups"]:
                if g in user_groups_lower:
                    matched = True
                    break

            # Check OUs (both in DN as an OU substring or directly matching a group name)
            if not matched:
                for ou in p["match_ous"]:
                    if (dn_lower and ou in dn_lower) or (ou in user_groups_lower):
                        matched = True
                        break

            # Check usernames
            if not matched and username:
                for regex in p["match_usernames"]:
                    if regex.search(username):
                        matched = True
                        break

            if matched:
                matched_policies.append(p["policy"])

        if matched_policies:
            min_len = max(p.get("length", 0) for p in matched_policies)
            req_complexity = any(p.get("complexity", False) for p in matched_policies)

            max_lifetime = min(
                (p.get("lifetime", 0) for p in matched_policies if p.get("lifetime", 0) > 0),
                default=0,
            )

            policy_name = ", ".join(p.get("name", "Unknown FGPP") for p in matched_policies)
        else:
            min_len = base_policy.get("length", 0)
            req_complexity = base_policy.get("complexity", False)
            max_lifetime = base_policy.get("lifetime", 0)
            policy_name = base_policy.get("name", "Base Policy")

        reasons = []
        if len(pwd) < min_len:
            reasons.append(f"Length < {min_len}")

        if req_complexity:
            has_upper = has_lower = has_digit = has_special = False
            count = 0
            for char in pwd:
                if not has_upper and char.isupper():
                    has_upper = True
                    count += 1
                    if count >= 3:
                        break
                elif not has_lower and char.islower():
                    has_lower = True
                    count += 1
                    if count >= 3:
                        break
                elif not has_digit and char.isdigit():
                    has_digit = True
                    count += 1
                    if count >= 3:
                        break
                elif not has_special and not char.isalnum():
                    has_special = True
                    count += 1
                    if count >= 3:
                        break

            if count < 3:
                reasons.append("Fails complexity")

        if max_lifetime > 0 and pwdlastset:
            age_days = (current_time - pwdlastset) / 86400.0
            if age_days > max_lifetime:
                reasons.append(f"Lifetime > {max_lifetime} days")

        if reasons:
            violations.append((user_id, policy_name, ", ".join(reasons)))

    if violations:
        c.executemany(
            "INSERT INTO policy_violations (user_id, policy_name, reason) VALUES (?, ?, ?)",
            violations,
        )
        conn.commit()

    conn.close()


def apply_domain_mapping(db_path: str, mapping_path: Optional[str], interactive: bool, bh_identities: Optional[set] = None, db_key: str = None):
    # If neither mapping is provided, there is nothing to do.
    if not mapping_path and not bh_identities:
        return

    logging.info("Applying domain mappings...")

    domain_mapping = {}
    if mapping_path:
        try:
            with open(mapping_path, "r", encoding="utf-8") as mf:
                domain_mapping = json.load(mf)
            # Ensure all keys and values are strings and values are lists
            domain_mapping = {str(k).lower(): [str(v) for v in vals] for k, vals in domain_mapping.items()}
        except Exception as e:
            logging.error(f"Failed to read domain mapping file: {e}")
            # If the mapping file fails and there are no BH identities, abort
            if not bh_identities:
                return

    conn = sqlite3.connect(db_path)
    if db_key:
        conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
    c = conn.cursor()

    c.execute("SELECT id, domain, username FROM users")
    all_users = c.fetchall()

    # Pre-calculate a fast lookup set for existing combinations to prevent N+1 queries
    c.execute("SELECT DISTINCT domain, username FROM users")
    existing_ntds_combos = {(r[0].lower(), r[1].lower()) for r in c}

    # Pre-calculate lowercased options for JSON mapping to avoid redundant string operations in the loop
    mapping_cache = {}
    for dom, opts in domain_mapping.items():
        mapping_cache[dom] = [(opt, opt.lower()) for opt in opts]

    updates = []

    # Optional prep for Bloodhound Auto Mapping
    bh_identities = bh_identities or set()
    bh_identities_by_user = {}
    for dom_lower, user_lower in bh_identities:
        bh_identities_by_user.setdefault(user_lower, []).append(dom_lower)

    for user_id, orig_domain, base_username in all_users:
        orig_domain_lower = orig_domain.lower()
        base_username_lower = base_username.lower()
        final_domain = orig_domain

        needs_json_mapping = True

        # Phase 1: Bloodhound Automatic Mapping
        if bh_identities:
            # First Check: Strict match (does this domain\username already exist in BH?)
            if (orig_domain_lower, base_username_lower) in bh_identities:
                # Exact match found, no remapping required
                needs_json_mapping = False
            else:
                # Second Check: Fallback match based on username only
                potential_bh_domains = bh_identities_by_user.get(base_username_lower, [])
                if potential_bh_domains:
                    valid_candidates = []
                    for pot_dom in potential_bh_domains:
                        # Check if this potential domain\user combo already exists in NTDS
                        if (pot_dom, base_username_lower) not in existing_ntds_combos:
                            valid_candidates.append(pot_dom)

                    if len(valid_candidates) == 1:
                        # Exactly one valid candidate that doesn't conflict with existing NTDS
                        final_domain = valid_candidates[0]
                        needs_json_mapping = False
                    # If 0 or >1 valid candidates, it's ambiguous or blocked. Fallback to JSON.

        # Phase 2: JSON Fallback Mapping
        if needs_json_mapping and orig_domain_lower in mapping_cache:
            options_cached = mapping_cache[orig_domain_lower]
            options = [opt for opt, _ in options_cached]

            if len(options_cached) == 1:
                final_domain = options_cached[0][0]
            elif len(options_cached) > 1:
                found_options = []
                for opt, opt_lower in options_cached:
                    if (opt_lower, base_username_lower) in existing_ntds_combos:
                        found_options.append(opt)

                if len(found_options) == 1:
                    # If exactly one option exists, select the other one that does NOT exist
                    found_opt_lower = found_options[0].lower()
                    other_options = [opt for opt, opt_lower in options_cached if opt_lower != found_opt_lower]
                    if other_options:
                        final_domain = other_options[0]
                    else:
                        final_domain = found_options[0]
                elif len(found_options) == 0:
                    # If neither exist, pick the first option
                    final_domain = options[0]
                else:
                    # If multiple exist (or all exist), leave as short domain (orig_domain)
                    final_domain = orig_domain

                # In cases 3 and 4 (neither exist or both exist), user can override in interactive mode
                if interactive and (len(found_options) == 0 or len(found_options) > 1):
                    print(f"\nAmbiguous mapping for NTDS account '{orig_domain}\\{base_username}'.")
                    print("Options:")
                    for idx, opt in enumerate(options):
                        print(f"  [{idx + 1}] {opt}")

                    default_opt = options[0] if len(found_options) == 0 else orig_domain
                    print(f"  [Enter] Default to: {default_opt}")

                    while True:
                        choice = input("Select an option (number) or press Enter for default: ").strip()
                        if choice == "":
                            final_domain = default_opt
                            break
                        try:
                            choice_idx = int(choice) - 1
                            if 0 <= choice_idx < len(options):
                                final_domain = options[choice_idx]
                                break
                            else:
                                print("Invalid choice.")
                        except ValueError:
                            print("Please enter a number.")

        # Ensure we maintain the case-sensitive string from BH if we got it from BH mapping,
        # but our bh_identities only have lowercase right now. If we changed it via BH mapping,
        # final_domain will be lowercase. That's OK since the codebase uses lowercase comparisons later.

        if final_domain != orig_domain:
            # Check for collision again (just to be completely sure for JSON fallback or interactive choices)
            if (final_domain.lower(), base_username.lower()) in existing_ntds_combos:
                if interactive:
                    print(f"\nCollision detected: User '{final_domain}\\{base_username}' already exists.")
                    print(f"Cannot rename '{orig_domain}\\{base_username}' to '{final_domain}'.")
                    print("Options: [1] Skip rename  [2] Enter a different domain name")
                    while True:
                        col_choice = input("Select an option (1 or 2): ").strip()
                        if col_choice == "1":
                            final_domain = orig_domain  # Skip
                            break
                        elif col_choice == "2":
                            new_dom = input("Enter new domain name: ").strip()
                            if new_dom:
                                final_domain = new_dom
                                break
                        else:
                            print("Invalid choice.")
                else:
                    logging.warning(
                        f"Collision detected: Cannot rename '{orig_domain}\\{base_username}' to '{final_domain}' because it already exists. Skipping rename."
                    )
                    final_domain = orig_domain

        if final_domain != orig_domain:
            updates.append((final_domain, user_id))
            # Update our tracker so we don't cause collisions within the same batch
            existing_ntds_combos.add((final_domain.lower(), base_username.lower()))

    if updates:
        # We process in batches
        batch_size = 100000
        for i in range(0, len(updates), batch_size):
            c.executemany("UPDATE users SET domain = ? WHERE id = ?", updates[i : i + batch_size])
        conn.commit()

    conn.close()


def main():

    args = parse_args()
    logging.info("Starting analysis...")

    db_path = "analysis.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    # Generate and insert admin credentials if not already present
    admin_password = None
    db_key = None
    is_interactive = sys.stdin.isatty() and sys.stdout.isatty()

    if is_interactive:
        print("\n" + "=" * 60)
        print("🔒 SECURITY NOTICE - INITIAL SETUP")
        print("=" * 60)
        print("Please set an initial password for the 'Administrator' web portal account.")
        while True:
            try:
                pwd1 = getpass.getpass("Web Portal Password: ")
                pwd2 = getpass.getpass("Confirm Web Portal Password: ")
                if pwd1 == pwd2 and len(pwd1) > 0:
                    admin_password = pwd1
                    break
                else:
                    print("Passwords do not match or are empty. Please try again.")
            except EOFError:
                break

        print("\nPlease set an encryption password for the SQLite Database (analysis.db).")
        while True:
            try:
                pwd1 = getpass.getpass("Database Encryption Password: ")
                pwd2 = getpass.getpass("Confirm Database Encryption Password: ")
                if pwd1 == pwd2 and len(pwd1) > 0:
                    db_key = pwd1
                    break
                else:
                    print("Passwords do not match or are empty. Please try again.")
            except EOFError:
                break
        print("=" * 60 + "\n")

    if not admin_password or not db_key:
        # Non-interactive fallback or if interactive prompt was aborted
        if not admin_password:
            admin_password = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*()") for _ in range(16))
        if not db_key:
            db_key = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*()") for _ in range(32))
        creds_file = "admin_credentials.txt"

        # Create file with strict permissions
        # We open with O_CREAT | O_WRONLY | O_TRUNC to ensure we create it
        # and set mode to 0o600
        fd = os.open(
            creds_file,
            os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(fd, "w") as f:
            f.write("=" * 60 + "\n")
            f.write("🔒 SECURITY NOTICE - CREDENTIALS & DB KEY\n")
            f.write("=" * 60 + "\n")
            f.write("Web Portal Login:\n")
            f.write("Username: Administrator\n")
            f.write(f"Password: {admin_password}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Database Encryption Key (ADPA_DB_KEY):\n{db_key}\n")
            f.write("=" * 60 + "\n")
            f.write("Please save these credentials. You will be prompted to change the web password upon first login.\n")
            f.write("You will need the Database Encryption Key to start the web portal.\n")
            f.write("=" * 60 + "\n")

        print("\n" + "=" * 60)
        print("🔒 SECURITY NOTICE - INITIAL SETUP")
        print("=" * 60)
        print("Running in non-interactive mode or prompts bypassed.")
        print(f"Random credentials and Database Encryption Key have been generated and saved securely to: {creds_file}")
        print("Please check this file for the login credentials and DB key.")
        print("=" * 60 + "\n")

    init_db(db_path, db_key)

    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
    c = conn.cursor()

    c.execute("SELECT 1 FROM web_users WHERE username = 'Administrator'")
    if not c.fetchone():
        admin_hash = generate_password_hash(admin_password)
        c.execute(
            "INSERT INTO web_users (username, password_hash, must_change_password) VALUES (?, ?, ?)",
            ("Administrator", admin_hash, 1),
        )
        conn.commit()

    conn.close()

    parse_potfile(args.potfile, db_path, db_key)
    logging.info("Loaded cracked hashes from potfile into DB.")

    parse_ntds(args.ntds, db_path, db_key)
    logging.info("Parsed users and hashes from NTDS into DB.")

    bh_identities = None
    if args.bloodhound:
        logging.info("Extracting Bloodhound identities for automatic domain mapping...")
        bh_identities = extract_bh_identities(args.bloodhound)

    apply_domain_mapping(db_path, args.domain_mapping, args.interactive, bh_identities, db_key)
    logging.info("Applied domain mappings.")

    if args.bloodhound:
        parse_bloodhound(args.bloodhound, db_path, db_key)
        logging.info("Parsed Bloodhound data into DB.")

        if args.enabled_only:
            logging.info("Applying global --enabled-only filter. Deleting disabled users and associated data from DB.")
            conn = sqlite3.connect(db_path)
            conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
            c = conn.cursor()

            # Delete from related tables first
            c.execute("DELETE FROM hashes WHERE user_id IN (SELECT id FROM users WHERE enabled = 0)")
            c.execute("DELETE FROM user_groups WHERE user_id IN (SELECT id FROM users WHERE enabled = 0)")
            c.execute("DELETE FROM policy_violations WHERE user_id IN (SELECT id FROM users WHERE enabled = 0)")

            # Delete from users table
            c.execute("DELETE FROM users WHERE enabled = 0")

            conn.commit()
            conn.close()

    high_value_groups = parse_high_value(args.high_value)
    policy = parse_policy(args.policy)

    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        ("high_value_groups", json.dumps(high_value_groups)),
    )
    conn.commit()
    conn.close()

    calculate_metrics(db_path, policy, args.redact, args.enabled_only, db_key)
    logging.info("Policy violations and metrics calculated.")

    logging.info("Pre-calculating shared hashes...")
    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA key='{db_key.replace("'", "''")}'")
    c = conn.cursor()
    c.execute("""
        INSERT INTO shared_hashes (nt_hash, cracked_password, count, shared_by)
        SELECT lower(h.nt_hash), h.cracked_password, COUNT(h.id),
               GROUP_CONCAT(u.domain || '\\' || u.username, ', ')
        FROM hashes h
        JOIN users u ON h.user_id = u.id
        WHERE h.is_history = 0 AND h.nt_hash IS NOT NULL AND h.nt_hash != ''
        GROUP BY lower(h.nt_hash)
        HAVING COUNT(h.id) > 1
    """)
    conn.commit()
    conn.close()
    logging.info("Shared hashes pre-calculated.")

    # HTML report generation removed in favor of dynamic portal.
    # Database is persisted.

    logging.info("Analysis complete. Database ready for dynamic portal.")


if __name__ == "__main__":
    main()
