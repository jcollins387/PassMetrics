import argparse
import sys
import json
import logging
import html
import sqlite3
import math
import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

@dataclass
class HashData:
    lm_hash: str
    nt_hash: str
    is_history: bool
    cracked_password: Optional[str] = None
    redacted_password: Optional[str] = None

@dataclass
class UserData:
    domain: str
    username: str
    rid: int
    enabled: bool = True  # Default true, overwritten by bloodhound if exists
    hashes: List[HashData] = field(default_factory=list)
    groups: Set[str] = field(default_factory=set)
    kerberoastable: bool = False
    asreproastable: bool = False
    pwdneverexpires: bool = False
    passwordnotreqd: bool = False

    @property
    def current_hash(self) -> Optional[HashData]:
        for h in self.hashes:
            if not h.is_history:
                return h
        return None

def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            username TEXT,
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
            reason TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_users_domain_username ON users(domain, username);
        CREATE INDEX IF NOT EXISTS idx_users_flags ON users(enabled, kerberoastable, asreproastable);
        CREATE INDEX IF NOT EXISTS idx_hashes_user_id ON hashes(user_id);
        CREATE INDEX IF NOT EXISTS idx_hashes_nt_hash ON hashes(nt_hash);
        CREATE INDEX IF NOT EXISTS idx_hashes_nt_hash_lower ON hashes(lower(nt_hash));
        CREATE INDEX IF NOT EXISTS idx_hashes_is_history ON hashes(is_history);
        CREATE INDEX IF NOT EXISTS idx_hashes_history_cracked ON hashes(is_history, cracked_password);
        CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups(user_id);
    ''')
    conn.commit()
    conn.close()


def parse_args():
    parser = argparse.ArgumentParser(description="Analyze NTDS hashes against a potfile and optional Bloodhound data.")

    parser.add_argument('--ntds', required=True, help="NTDS file containing password hashes")
    parser.add_argument('--potfile', required=True, help="Hashcat potfile containing the cracked hashes")
    parser.add_argument('--bloodhound', nargs='+', help="(OPTIONAL) One or more json files generated from bloodhound")
    parser.add_argument('--policy', help="(OPTIONAL) JSON file containing password policy")
    parser.add_argument('--high-value', help="(OPTIONAL) File containing high value groups/OUs")
    parser.add_argument('--enabled-only', action='store_true', help="(OPTIONAL) Show only 'enabled' users (IGNORE IF NO BLOODHOUND)")
    parser.add_argument('--redact', action='store_true', help="(OPTIONAL) Redact the passwords and hashes in reports")
    parser.add_argument('--outdir', help="(OPTIONAL) Directory to output HTML reports to. Defaults to report_<timestamp>")

    return parser.parse_args()

def parse_potfile(potfile_path: str, db_path: str):
    """Parses hashcat potfile and inserts hashes into the DB."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    batch = []

    with open(potfile_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Hashcat potfile format is hash:password
            parts = line.split(':', 1)
            if len(parts) == 2:
                # NTHashes in potfile are usually 32 chars long. We index by lowercase to avoid case issues
                h, p = parts
                if len(h) == 32:
                    if p.startswith('$HEX[') and p.endswith(']'):
                        try:
                            p = bytes.fromhex(p[5:-1]).decode('utf-8', errors='replace')
                        except ValueError:
                            pass
                    batch.append((h.lower(), p))

            if len(batch) >= 100000:
                c.executemany("INSERT OR IGNORE INTO cracked_hashes (nt_hash, cracked_password) VALUES (?, ?)", batch)
                batch = []

    if batch:
        c.executemany("INSERT OR IGNORE INTO cracked_hashes (nt_hash, cracked_password) VALUES (?, ?)", batch)

    conn.commit()
    conn.close()

def parse_ntds(ntds_path: str, db_path: str):
    """Parses NTDS dump, skips krbtgt/machine accounts, inserts directly into DB."""
    logging.info(f"Parsing NTDS file: {ntds_path}")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    users_batch = []
    hashes_batch = []

    user_key_to_id = {} # map domain\username -> internal sqlite rowid
    next_user_id = 1

    count = 0
    with open(ntds_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            count += 1
            if count % 100000 == 0:
                logging.info(f"Processed {count} lines from NTDS...")

            line = line.strip()
            if not line:
                continue

            # Expected format (e.g. impacket-secretsdump):
            # domain\username:RID:lmhash:nthash:::
            parts = line.split(':')
            if len(parts) < 4:
                continue

            domain_user = parts[0]
            if '\\' in domain_user:
                domain, username = domain_user.split('\\', 1)
            else:
                domain, username = "UNKNOWN", domain_user

            try:
                rid = int(parts[1])
            except ValueError:
                continue

            lm_hash = parts[2]
            nt_hash = parts[3]

            # Identify if it's history
            is_history = False
            base_username = username
            # NTDS extraction often adds _history followed by some ID, or simply _history
            import re
            history_match = re.search(r'_history\d*$', username, re.IGNORECASE)
            if history_match:
                base_username = username[:history_match.start()]
                is_history = True

            # Skip KRBTGT and machine accounts
            if base_username.lower() == 'krbtgt' or base_username.endswith('$'):
                continue

            key = f"{domain}\\{base_username}".lower()

            if key not in user_key_to_id:
                user_key_to_id[key] = next_user_id
                users_batch.append((next_user_id, domain, base_username, rid))
                next_user_id += 1

            user_id = user_key_to_id[key]
            hashes_batch.append((user_id, lm_hash, nt_hash, is_history))

            if len(users_batch) >= 100000:
                c.executemany("INSERT INTO users (id, domain, username, rid) VALUES (?, ?, ?, ?)", users_batch)
                users_batch = []

            if len(hashes_batch) >= 100000:
                c.executemany("INSERT INTO hashes (user_id, lm_hash, nt_hash, is_history) VALUES (?, ?, ?, ?)", hashes_batch)
                hashes_batch = []

    if users_batch:
        c.executemany("INSERT INTO users (id, domain, username, rid) VALUES (?, ?, ?, ?)", users_batch)
    if hashes_batch:
        c.executemany("INSERT INTO hashes (user_id, lm_hash, nt_hash, is_history) VALUES (?, ?, ?, ?)", hashes_batch)

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

def _build_identifier_map(bh_files: List[str]) -> Dict[str, str]:
    identifier_map = {}
    for bh_file in bh_files:
        with open(bh_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                continue

            data_list = []
            if 'data' in data:
                data_list = data['data']
            elif 'users' in data:
                data_list = data['users']
            elif 'groups' in data:
                data_list = data['groups']
            else:
                if isinstance(data, list):
                    data_list = data

            for item in data_list:
                props = item.get('Properties', {})
                obj_id = item.get('ObjectIdentifier')
                name = props.get('name')
                if obj_id and name:
                    identifier_map[obj_id] = name
    return identifier_map

def _process_bh_file(args):
    bh_file, global_identifier_map = args
    user_updates = []
    group_inserts = []

    with open(bh_file, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            logging.error(f"Failed to parse Bloodhound file {bh_file}")
            return user_updates, group_inserts

        data_list = []
        if 'data' in data:
            data_list = data['data']
        elif 'users' in data:
            data_list = data['users']
            for item in data_list:
                item['type'] = 'User'
        elif 'groups' in data:
            data_list = data['groups']
            for item in data_list:
                item['type'] = 'Group'
        else:
            if isinstance(data, list):
                data_list = data
            else:
                return user_updates, group_inserts

        for item in data_list:
            item_type = item.get('type', item.get('Type', '')).upper()
            props = item.get('Properties', {})

            if item_type == 'USER' or (not item_type and props.get('samaccountname')):
                domain = props.get('domain', '').split('.')[0]
                samaccountname = props.get('samaccountname', '')
                if samaccountname:
                    user_updates.append({
                        'domain': domain.lower(),
                        'samaccountname': samaccountname.lower(),
                        'enabled': props.get('enabled', True),
                        'pwdneverexpires': props.get('pwdneverexpires', False),
                        'passwordnotreqd': props.get('passwordnotreqd', False),
                        'kerberoastable': props.get('hasspn', False),
                        'asreproastable': props.get('dontreqpreauth', False),
                        'distinguishedname': props.get('distinguishedname', ''),
                        'pwdlastset': props.get('pwdlastset', 0)
                    })

            if item_type == 'GROUP' or (not item_type and 'Members' in item):
                group_name = props.get('name', '').split('@')[0] if props.get('name') else ''
                if group_name:
                    for member in item.get('Members', []):
                        m_type = member.get('ObjectType', member.get('type', '')).upper()
                        if m_type == 'USER':
                            m_name = member.get('ObjectName', member.get('name', ''))
                            if not m_name and member.get('ObjectIdentifier'):
                                m_name = global_identifier_map.get(member.get('ObjectIdentifier'), '')
                            if m_name:
                                m_parts = m_name.split('@')
                                m_user = m_parts[0].lower()
                                m_dom = m_parts[1].split('.')[0].lower() if len(m_parts) > 1 else ''
                                group_inserts.append((m_dom, m_user, group_name))

    return user_updates, group_inserts


def parse_bloodhound(bh_files: List[str], db_path: str):
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

        batch = [(u['domain'], u['samaccountname'], u['enabled'], u['pwdneverexpires'], u['passwordnotreqd'], u['kerberoastable'], u['asreproastable'], u['distinguishedname'], u['pwdlastset']) for u in all_user_updates]
        c.executemany("INSERT INTO bh_users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", batch)

        # Apply strict match (domain + username)
        c.execute("""
            UPDATE users SET
                enabled = (SELECT enabled FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                pwdneverexpires = (SELECT pwdneverexpires FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                passwordnotreqd = (SELECT passwordnotreqd FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                kerberoastable = (SELECT kerberoastable FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                asreproastable = (SELECT asreproastable FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                distinguishedname = (SELECT distinguishedname FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                pwdlastset = (SELECT pwdlastset FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username))
            WHERE EXISTS (
                SELECT 1 FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)
            )
        """)

        # Apply fallback match (username only for users that weren't matched above)
        # This mirrors the fallback_index logic in the original script
        c.execute("""
            UPDATE users SET
                enabled = (SELECT enabled FROM bh_users WHERE bh_users.username = lower(users.username) LIMIT 1),
                pwdneverexpires = (SELECT pwdneverexpires FROM bh_users WHERE bh_users.username = lower(users.username) LIMIT 1),
                passwordnotreqd = (SELECT passwordnotreqd FROM bh_users WHERE bh_users.username = lower(users.username) LIMIT 1),
                kerberoastable = (SELECT kerberoastable FROM bh_users WHERE bh_users.username = lower(users.username) LIMIT 1),
                asreproastable = (SELECT asreproastable FROM bh_users WHERE bh_users.username = lower(users.username) LIMIT 1),
                distinguishedname = (SELECT distinguishedname FROM bh_users WHERE bh_users.username = lower(users.username) LIMIT 1),
                pwdlastset = (SELECT pwdlastset FROM bh_users WHERE bh_users.username = lower(users.username) LIMIT 1)
            WHERE NOT EXISTS (
                SELECT 1 FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)
            ) AND EXISTS (
                SELECT 1 FROM bh_users WHERE bh_users.username = lower(users.username)
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
        return ['Domain Admins', 'Enterprise Admins']

    groups = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                val = line.strip()
                if val:
                    groups.append(val)
        return groups
    except Exception as e:
        logging.error(f"Failed to read high value file: {e}")
        return ['Domain Admins', 'Enterprise Admins']

def parse_policy(file_path: Optional[str]) -> Dict:
    """Returns policy dict."""
    if not file_path:
        return {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to read policy file: {e}")
        return {}

def redact_string(value: str) -> str:
    if not value:
        return value
    if len(value) <= 2:
        return '*' * len(value)
    return value[0] + '*' * (len(value) - 2) + value[-1]

def calculate_metrics(db_path: str, policy: Dict, redact: bool, enabled_only: bool):
    logging.info("Calculating policy violations and database setup...")
    conn = sqlite3.connect(db_path)
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
        SELECT u.id, h.cracked_password, group_concat(lower(ug.group_name)), u.distinguishedname, u.pwdlastset
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

    for row in c.fetchall():
        user_id = row[0]
        pwd = row[1]
        user_groups_lower = row[2].split(",") if row[2] else []
        dn_lower = row[3].lower() if row[3] else ""
        pwdlastset = row[4]

        applicable_policy = base_policy
        for group, g_policy in fgpp_policies.items():
            group_lower = group.lower()
            if group_lower in user_groups_lower or (dn_lower and f"{group_lower}," in f"{dn_lower},"):
                applicable_policy = g_policy
                break

        if applicable_policy:
            min_len = applicable_policy.get("length", 0)
            req_complexity = applicable_policy.get("complexity", False)
            max_lifetime = applicable_policy.get("lifetime", 0)

            reasons = []
            if len(pwd) < min_len:
                reasons.append(f"Length < {min_len}")

            if req_complexity:
                has_upper = any(char.isupper() for char in pwd)
                has_lower = any(char.islower() for char in pwd)
                has_digit = any(char.isdigit() for char in pwd)
                has_special = any(not char.isalnum() for char in pwd)
                if sum([has_upper, has_lower, has_digit, has_special]) < 3:
                    reasons.append("Fails complexity")

            if max_lifetime > 0 and pwdlastset:
                age_days = (current_time - pwdlastset) / 86400.0
                if age_days > max_lifetime:
                    reasons.append(f"Lifetime > {max_lifetime} days")

            if reasons:
                violations.append((user_id, ", ".join(reasons)))

    if violations:
        c.executemany("INSERT INTO policy_violations (user_id, reason) VALUES (?, ?)", violations)
        conn.commit()

    conn.close()

import os


def main():
    args = parse_args()
    logging.info("Starting analysis...")

    db_path = "analysis.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    init_db(db_path)

    parse_potfile(args.potfile, db_path)
    logging.info("Loaded cracked hashes from potfile into DB.")

    parse_ntds(args.ntds, db_path)
    logging.info("Parsed users and hashes from NTDS into DB.")

    if args.bloodhound:
        parse_bloodhound(args.bloodhound, db_path)
        logging.info("Parsed Bloodhound data into DB.")

    high_value_groups = parse_high_value(args.high_value)
    policy = parse_policy(args.policy)

    import json
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("high_value_groups", json.dumps(high_value_groups)))
    conn.commit()
    conn.close()

    calculate_metrics(db_path, policy, args.redact, args.enabled_only)
    logging.info("Policy violations and metrics calculated.")

    # HTML report generation removed in favor of dynamic portal.
    # Database is persisted.

    logging.info("Analysis complete. Database ready for dynamic portal.")

if __name__ == '__main__':
    main()
