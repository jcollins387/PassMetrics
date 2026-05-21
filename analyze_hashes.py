import argparse
import sys
import json
import logging
import html
import sqlite3
import math
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
            asreproastable BOOLEAN DEFAULT 0
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

        CREATE INDEX IF NOT EXISTS idx_users_domain_username ON users(domain, username);
        CREATE INDEX IF NOT EXISTS idx_hashes_user_id ON hashes(user_id);
        CREATE INDEX IF NOT EXISTS idx_hashes_nt_hash ON hashes(nt_hash);
        CREATE INDEX IF NOT EXISTS idx_hashes_is_history ON hashes(is_history);
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

def _process_bh_file(bh_file: str):
    user_updates = []
    group_inserts = []

    with open(bh_file, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            logging.error(f"Failed to parse Bloodhound file {bh_file}")
            return user_updates, group_inserts

        if 'data' not in data:
            return user_updates, group_inserts

        for item in data['data']:
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
                        'asreproastable': props.get('dontreqpreauth', False)
                    })

            if item_type == 'GROUP' or (not item_type and 'Members' in item):
                group_name = props.get('name', '').split('@')[0] if props.get('name') else ''
                if group_name:
                    for member in item.get('Members', []):
                        m_type = member.get('ObjectType', member.get('type', '')).upper()
                        if m_type == 'USER':
                            m_name = member.get('ObjectName', member.get('name', ''))
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

    with concurrent.futures.ProcessPoolExecutor() as executor:
        for updates, inserts in executor.map(_process_bh_file, bh_files):
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
                asreproastable BOOLEAN
            );
            CREATE INDEX idx_bh_users ON bh_users(domain, username);
            CREATE INDEX idx_bh_users_username ON bh_users(username);
        """)

        batch = [(u['domain'], u['samaccountname'], u['enabled'], u['pwdneverexpires'], u['passwordnotreqd'], u['kerberoastable'], u['asreproastable']) for u in all_user_updates]
        c.executemany("INSERT INTO bh_users VALUES (?, ?, ?, ?, ?, ?, ?)", batch)

        # Apply strict match (domain + username)
        c.execute("""
            UPDATE users SET
                enabled = (SELECT enabled FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                pwdneverexpires = (SELECT pwdneverexpires FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                passwordnotreqd = (SELECT passwordnotreqd FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                kerberoastable = (SELECT kerberoastable FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username)),
                asreproastable = (SELECT asreproastable FROM bh_users WHERE bh_users.domain = lower(users.domain) AND bh_users.username = lower(users.username))
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
                asreproastable = (SELECT asreproastable FROM bh_users WHERE bh_users.username = lower(users.username) LIMIT 1)
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

def calculate_metrics(db_path: str, high_value_groups: List[str], policy: Dict, redact: bool, enabled_only: bool) -> Dict:
    logging.info("Calculating metrics using SQLite...")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    enabled_filter = "AND u.enabled = 1" if enabled_only else ""

    metrics = {
        'total_accounts': 0,
        'total_passwords': 0,
        'total_cracked': 0,
        'unique_passwords_count': 0,
        'unique_cracked_count': 0,
        'kerberoastable_cracked_count': 0,
        'asreproastable_cracked_count': 0,
        'high_value_cracked_count': 0,
        'pwdneverexpires_count': 0,
        'passwordnotreqd_count': 0,
        'lm_hashes_count': 0,
        'shared_passwords_count': 0,
        'policy_violations_count': 0,
        'password_lengths': {},
        'enabled_only_flag': enabled_only
    }

    # Redact cracked passwords in the DB if requested
    if redact:
        logging.info("Redacting passwords in DB...")
        c.execute("""
            UPDATE hashes
            SET redacted_password = CASE
                WHEN length(cracked_password) <= 2 THEN substr('********************************', 1, length(cracked_password))
                ELSE substr(cracked_password, 1, 1) || substr('********************************', 1, length(cracked_password)-2) || substr(cracked_password, -1, 1)
            END
            WHERE cracked_password IS NOT NULL
        """)
        conn.commit()

    # Totals
    c.execute(f"SELECT COUNT(*) FROM users u WHERE 1=1 {enabled_filter}")
    metrics['total_accounts'] = c.fetchone()[0]

    c.execute(f"SELECT COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 {enabled_filter}")
    metrics['total_passwords'] = c.fetchone()[0]

    c.execute(f"SELECT COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL {enabled_filter}")
    metrics['total_cracked'] = c.fetchone()[0]

    c.execute(f"SELECT COUNT(DISTINCT lower(h.nt_hash)) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 {enabled_filter}")
    metrics['unique_passwords_count'] = c.fetchone()[0]

    c.execute(f"SELECT COUNT(DISTINCT h.cracked_password) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL {enabled_filter}")
    metrics['unique_cracked_count'] = c.fetchone()[0]

    # Roastable cracked
    c.execute(f"SELECT COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL AND u.kerberoastable = 1 {enabled_filter}")
    metrics['kerberoastable_cracked_count'] = c.fetchone()[0]

    c.execute(f"SELECT COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL AND u.asreproastable = 1 {enabled_filter}")
    metrics['asreproastable_cracked_count'] = c.fetchone()[0]

    # High Value cracked
    hv_placeholders = ','.join('?' * len(high_value_groups))
    hv_params = [g.lower() for g in high_value_groups]
    c.execute(f"""
        SELECT COUNT(DISTINCT u.id)
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        JOIN user_groups ug ON u.id = ug.user_id
        WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL
        AND lower(ug.group_name) IN ({hv_placeholders}) {enabled_filter}
    """, hv_params)
    metrics['high_value_cracked_count'] = c.fetchone()[0]

    # Flags
    c.execute(f"SELECT COUNT(*) FROM users u WHERE u.pwdneverexpires = 1 {enabled_filter}")
    metrics['pwdneverexpires_count'] = c.fetchone()[0]

    c.execute(f"SELECT COUNT(*) FROM users u WHERE u.passwordnotreqd = 1 {enabled_filter}")
    metrics['passwordnotreqd_count'] = c.fetchone()[0]

    # LM Hashes
    c.execute(f"SELECT COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND lower(h.lm_hash) != 'aad3b435b51404eeaad3b435b51404ee' {enabled_filter}")
    metrics['lm_hashes_count'] = c.fetchone()[0]

    # Shared Passwords
    c.execute(f"""
        SELECT COUNT(*) FROM (
            SELECT lower(h.nt_hash) FROM hashes h JOIN users u ON h.user_id = u.id
            WHERE h.is_history = 0 {enabled_filter}
            GROUP BY lower(h.nt_hash) HAVING COUNT(h.id) > 1
        )
    """)
    shared_hashes_count = c.fetchone()[0]

    # We want the total accounts sharing passwords, not just the number of unique shared hashes
    c.execute(f"""
        SELECT COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id
        WHERE h.is_history = 0 {enabled_filter} AND lower(h.nt_hash) IN (
            SELECT lower(h2.nt_hash) FROM hashes h2 JOIN users u2 ON h2.user_id = u2.id
            WHERE h2.is_history = 0 {enabled_filter}
            GROUP BY lower(h2.nt_hash) HAVING COUNT(h2.id) > 1
        )
    """)
    metrics['shared_passwords_count'] = c.fetchone()[0]

    # Password Lengths
    c.execute(f"SELECT length(h.cracked_password), COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL {enabled_filter} GROUP BY length(h.cracked_password)")
    for row in c.fetchall():
        metrics['password_lengths'][row[0]] = row[1]

    # Policy Violations
    logging.info("Calculating policy violations...")
    c.execute(f"""
        SELECT u.id, h.cracked_password, group_concat(lower(ug.group_name))
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        LEFT JOIN user_groups ug ON u.id = ug.user_id
        WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL {enabled_filter}
        GROUP BY u.id
    """)

    violations = []
    fgpp_policies = policy.get('fgpp', {})
    base_policy = policy.get('base', {})

    for row in c.fetchall():
        user_id = row[0]
        pwd = row[1]
        user_groups_lower = row[2].split(',') if row[2] else []

        applicable_policy = base_policy
        for group, g_policy in fgpp_policies.items():
            if group.lower() in user_groups_lower:
                applicable_policy = g_policy
                break

        if applicable_policy:
            min_len = applicable_policy.get('length', 0)
            req_complexity = applicable_policy.get('complexity', False)

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

            if reasons:
                violations.append((user_id, ", ".join(reasons)))

    if violations:
        c.executemany("INSERT INTO policy_violations (user_id, reason) VALUES (?, ?)", violations)
        conn.commit()

    metrics['policy_violations_count'] = len(violations)

    conn.close()
    return metrics

import os
import time

def generate_html_report(db_path: str, metrics: Dict, high_value_groups: List[str], redact: bool, output_dir: Optional[str] = None):
    logging.info("Generating HTML reports...")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    if not output_dir:
        timestamp = int(time.time())
        output_dir = f"report_{timestamp}"

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    base_html_template = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Password Analysis Report</title>
<style>
    body {{ font-family: Arial, sans-serif; background: #f4f4f4; color: #333; margin: 20px; }}
    h1, h2, h3 {{ color: #444; }}
    .card {{ background: #fff; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
    .metric {{ font-size: 24px; font-weight: bold; color: #d9534f; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #eee; cursor: pointer; }}
    .bar-chart {{ display: flex; align-items: flex-end; height: 200px; gap: 10px; border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 20px; }}
    .bar-col {{ display: flex; flex-direction: column; align-items: center; justify-content: flex-end; width: 40px; }}
    .bar {{ background: #5cb85c; width: 30px; text-align: center; color: white; font-size: 10px; border-radius: 3px 3px 0 0; }}
    .bar-label {{ margin-top: 5px; font-size: 12px; }}
    input[type="text"] {{ padding: 5px; margin-bottom: 10px; width: 100%; max-width: 300px; }}
    nav {{ background: #fff; padding: 10px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
    nav a {{ margin-right: 15px; text-decoration: none; color: #337ab7; font-weight: bold; }}
    nav a:hover {{ text-decoration: underline; }}
    .pagination {{ margin-top: 15px; text-align: center; }}
    .pagination a {{ text-decoration: none; padding: 5px 10px; background: #337ab7; color: #fff; border-radius: 3px; margin: 0 5px; }}
    .pagination a:hover {{ background: #23527c; }}
    .pagination span {{ padding: 5px 10px; margin: 0 5px; }}
</style>
<script>
    function filterTable(inputId, tableId) {{
        var input, filter, table, tr, td, i, j, txtValue;
        input = document.getElementById(inputId);
        filter = input.value.toUpperCase();
        table = document.getElementById(tableId);
        tr = table.getElementsByTagName("tr");
        // start at 1 to skip header, but check if row has class ignore-filter
        for (i = 1; i < tr.length; i++) {{
            if (tr[i].classList.contains('ignore-filter')) continue;
            tr[i].style.display = "none";
            td = tr[i].getElementsByTagName("td");
            for (j = 0; j < td.length; j++) {{
                if (td[j]) {{
                    txtValue = td[j].textContent || td[j].innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {{
                        tr[i].style.display = "";
                        break;
                    }}
                }}
            }}
        }}
    }}

    function toggleRows(tableId, selectId) {{
        var select = document.getElementById(selectId);
        var num = parseInt(select.value, 10);
        var table = document.getElementById(tableId);
        var trs = table.getElementsByClassName('data-row');
        for (var i = 0; i < trs.length; i++) {{
            if (i < num) {{
                trs[i].style.display = '';
            }} else {{
                trs[i].style.display = 'none';
            }}
        }}
    }}

    function toggleAccounts(hashId) {{
        var row = document.getElementById(hashId);
        if (row.style.display === 'none' || row.style.display === '') {{
            row.style.display = 'table-row';
        }} else {{
            row.style.display = 'none';
        }}
    }}
</script>
</head>
<body>
    <nav>
        <a href="index.html">Summary</a>
        <a href="lengths.html">Password Lengths</a>
        <a href="shared.html">Shared Passwords</a>
        <a href="lm_hashes.html">LM Hashes</a>
        <a href="policy.html">Policy Violations</a>
        <a href="high_value.html">High Value</a>
        <a href="kerberoastable.html">Kerberoastable</a>
        <a href="asreproastable.html">ASREPRoastable</a>
        <a href="flags.html">Account Flags</a>
        <a href="history.html">Password History</a>
    </nav>
    <h1>Password Analysis Report: {page_title}</h1>

    {content}

</body>
</html>"""

    # Generate Length Bars
    lengths = metrics['password_lengths']
    max_count = max(lengths.values()) if lengths else 1
    bars_html = ""
    for length in sorted(lengths.keys()):
        count = lengths[length]
        height_px = max(10, int((count / max_count) * 180)) # max height 180px
        bars_html += f'<div class="bar-col"><div class="bar" style="height:{height_px}px" title="{count} passwords">{count}</div><div class="bar-label">{length}</div></div>'

    def write_page(filename, title, content):
        path = os.path.join(output_dir, filename)
        final_html = base_html_template.format(page_title=title, content=content)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(final_html)

    def generate_pagination_html(base_name, current_page, total_pages):
        if total_pages <= 1:
            return ""

        html_out = '<div class="pagination">'
        if current_page > 1:
            html_out += f'<a href="{base_name}_{current_page - 1}.html">Previous</a>'
        html_out += f'<span>Page {current_page} of {total_pages}</span>'
        if current_page < total_pages:
            html_out += f'<a href="{base_name}_{current_page + 1}.html">Next</a>'
        html_out += '</div>'
        return html_out

    def generate_paginated_pages(base_name, title, headers, query, count_query, params=(), rows_per_page=1000):
        c.execute(count_query, params)
        total_rows = c.fetchone()[0]
        total_pages = math.ceil(total_rows / rows_per_page)

        if total_pages == 0:
            content = f'<div class="card"><h2>{title}</h2><p>No data available.</p></div>'
            write_page(f"{base_name}_1.html", title, content)
            return

        for page in range(1, total_pages + 1):
            offset = (page - 1) * rows_per_page

            # Since limit and offset can't easily be parameterized with the exact array size in sqlite in the same way, we append them
            page_query = query + f" LIMIT {rows_per_page} OFFSET {offset}"
            c.execute(page_query, params)
            rows = c.fetchall()

            table_html = f'<div class="card"><h2>{title}</h2>'
            table_id = f"{base_name}Table"
            table_html += f'<input type="text" id="{table_id}Filter" onkeyup="filterTable(\'{table_id}Filter\', \'{table_id}\')" placeholder="Filter...">'
            table_html += f'<table id="{table_id}"><tr>'
            for h in headers:
                table_html += f'<th>{h}</th>'
            table_html += '</tr>'
            for row in rows:
                table_html += '<tr>'
                for cell in row:
                    escaped_cell = html.escape(str(cell)) if cell is not None else ''
                    table_html += f'<td>{escaped_cell}</td>'
                table_html += '</tr>'
            table_html += '</table></div>'

            pagination = generate_pagination_html(base_name, page, total_pages)
            final_content = pagination + table_html + pagination

            write_page(f"{base_name}_{page}.html", title, final_content)

    # --- Index Page ---
    index_content = f"""
    <div class="card">
        <h2>Summary Metrics</h2>
        <p>Total Evaluated Accounts: <span class="metric">{metrics['total_accounts']}</span></p>
        <p>Total Passwords: {metrics['total_passwords']} | Total Cracked: <span class="metric">{metrics['total_cracked']}</span></p>
        <p>Unique Passwords: {metrics['unique_passwords_count']} | Unique Cracked: <span class="metric">{metrics['unique_cracked_count']}</span></p>
        <p>Kerberoastable & Cracked: <span class="metric">{metrics['kerberoastable_cracked_count']}</span></p>
        <p>ASREPRoastable & Cracked: <span class="metric">{metrics['asreproastable_cracked_count']}</span></p>
        <p>High Value Accounts Cracked: <span class="metric">{metrics['high_value_cracked_count']}</span></p>
        <p>Accounts with Password Not Required: <span class="metric">{metrics['passwordnotreqd_count']}</span></p>
        <p>Accounts with Password Never Expires: <span class="metric">{metrics['pwdneverexpires_count']}</span></p>
        <p>Accounts with LM Hashes: <span class="metric">{metrics['lm_hashes_count']}</span></p>
        <p>Accounts Sharing Passwords: <span class="metric">{metrics['shared_passwords_count']}</span></p>
        <p>Accounts with Policy Violations: <span class="metric">{metrics['policy_violations_count']}</span></p>
    </div>

    <div class="card">
        <h2>Password Length Distribution</h2>
        <div class="bar-chart">
            {bars_html}
        </div>
    </div>
    """
    write_page("index.html", "Summary", index_content)

    enabled_filter = "AND u.enabled = 1" if metrics.get('enabled_only_flag') else ""
    pwd_col = "h.redacted_password" if redact else "h.cracked_password"

    # --- Password Lengths Page ---
    c.execute(f"""
        SELECT length(cracked_password) as pw_len, cracked_password
        FROM hashes h JOIN users u ON h.user_id = u.id
        WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL {enabled_filter}
        GROUP BY cracked_password
        ORDER BY pw_len ASC
        LIMIT 100
    """)
    shortest = c.fetchall()

    c.execute(f"""
        SELECT length(cracked_password) as pw_len, cracked_password
        FROM hashes h JOIN users u ON h.user_id = u.id
        WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL {enabled_filter}
        GROUP BY cracked_password
        ORDER BY pw_len DESC
        LIMIT 100
    """)
    longest = c.fetchall()

    def generate_length_table(title, table_id, select_id, data):
        html_str = f'<div class="card"><h2>{title}</h2>'
        html_str += f'<label for="{select_id}">Show rows: </label>'
        html_str += f'<select id="{select_id}" onchange="toggleRows(\'{table_id}\', \'{select_id}\')">'
        html_str += '<option value="10" selected>10</option>'
        html_str += '<option value="25">25</option>'
        html_str += '<option value="50">50</option>'
        html_str += '<option value="100">100</option>'
        html_str += '</select>'
        html_str += f'<table id="{table_id}">'
        html_str += '<tr><th>Length</th><th>Password</th></tr>'
        for i, row in enumerate(data):
            display_style = '' if i < 10 else 'style="display:none;"'
            pw_val = ('*' * len(row[1]) if len(row[1]) <= 2 else row[1][0] + '*' * (len(row[1])-2) + row[1][-1]) if redact else row[1]
            html_str += f'<tr class="data-row" {display_style}><td>{row[0]}</td><td>{html.escape(pw_val)}</td></tr>'
        html_str += '</table></div>'
        return html_str

    lengths_content = generate_length_table("Top 100 Shortest Passwords", "shortTable", "shortSelect", shortest)
    lengths_content += generate_length_table("Top 100 Longest Passwords", "longTable", "longSelect", longest)
    write_page("lengths.html", "Password Lengths", lengths_content)

    # --- Shared Passwords Page ---
    q_shared_count = f"""
        SELECT COUNT(*) FROM (
            SELECT lower(h.nt_hash) FROM hashes h JOIN users u ON h.user_id = u.id
            WHERE h.is_history = 0 {enabled_filter}
            GROUP BY lower(h.nt_hash) HAVING COUNT(h.id) > 1
        )
    """
    c.execute(q_shared_count)
    total_shared_hashes = c.fetchone()[0]
    total_shared_pages = math.ceil(total_shared_hashes / 1000)

    if total_shared_pages == 0:
        content = f'<div class="card"><h2>Shared Passwords</h2><p>No data available.</p></div>'
        write_page("shared_1.html", "Shared Passwords", content)
    else:
        for page in range(1, total_shared_pages + 1):
            offset = (page - 1) * 1000
            # Get the distinct shared hashes
            c.execute(f"""
                SELECT lower(h.nt_hash), {pwd_col}, COUNT(h.id) as count
                FROM hashes h JOIN users u ON h.user_id = u.id
                WHERE h.is_history = 0 {enabled_filter}
                GROUP BY lower(h.nt_hash) HAVING COUNT(h.id) > 1
                ORDER BY count DESC
                LIMIT 1000 OFFSET {offset}
            """)
            shared_page = c.fetchall()

            shared_rows_html = ""
            for i, row in enumerate(shared_page):
                nt_hash = row[0]
                pwd_display = html.escape(row[1] if row[1] else "")
                hash_display = ('*' * 32 if redact else nt_hash)
                count = row[2]

                # Fetch users for this hash
                c.execute(f"""
                    SELECT u.domain, u.username
                    FROM hashes h JOIN users u ON h.user_id = u.id
                    WHERE lower(h.nt_hash) = ? AND h.is_history = 0 {enabled_filter}
                    ORDER BY u.domain, u.username
                """, (nt_hash,))
                users_for_hash = c.fetchall()

                row_id = f"hash_row_{page}_{i}"
                shared_rows_html += f"""
                    <tr>
                        <td>{hash_display}</td>
                        <td>{pwd_display}</td>
                        <td>{count}</td>
                        <td><a href="javascript:void(0);" onclick="toggleAccounts('{row_id}')">View Accounts</a></td>
                    </tr>
                    <tr id="{row_id}" class="ignore-filter" style="display:none; background-color: #f9f9f9;">
                        <td colspan="4">
                            <ul>
                                {"".join(f"<li>{html.escape(u[0])}\\\\{html.escape(u[1])}</li>" for u in users_for_hash)}
                            </ul>
                        </td>
                    </tr>
                """

            table_html = f"""
            <div class="card">
                <h2>Shared Passwords</h2>
                <input type="text" id="sharedFilter" onkeyup="filterTable('sharedFilter', 'sharedTable')" placeholder="Filter by Hash, Password or Count...">
                <table id="sharedTable">
                    <tr><th>NT Hash</th><th>Password</th><th>Count</th><th>Action</th></tr>
                    {shared_rows_html}
                </table>
            </div>
            """

            pagination = generate_pagination_html("shared", page, total_shared_pages)
            final_content = pagination + table_html + pagination

            write_page(f"shared_{page}.html", "Shared Passwords", final_content)

    # --- LM Hashes Page ---
    q_lm_count = f"SELECT COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND lower(h.lm_hash) != 'aad3b435b51404eeaad3b435b51404ee' {enabled_filter}"
    hash_col = "substr('********************************', 1, length(h.lm_hash))" if redact else "h.lm_hash"
    q_lm = f"SELECT u.domain, u.username, {hash_col} FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND lower(h.lm_hash) != 'aad3b435b51404eeaad3b435b51404ee' {enabled_filter} ORDER BY u.domain, u.username"
    generate_paginated_pages("lm_hashes", "Accounts with LM Hashes", ["Domain", "Username", "LM Hash"], q_lm, q_lm_count)

    # --- Policy Violations Page ---
    q_pv_count = f"SELECT COUNT(*) FROM policy_violations pv JOIN users u ON pv.user_id = u.id WHERE 1=1 {enabled_filter}"
    q_pv = f"""
        SELECT u.domain, u.username, {pwd_col}, pv.reason
        FROM policy_violations pv
        JOIN users u ON pv.user_id = u.id
        JOIN hashes h ON u.id = h.user_id AND h.is_history = 0
        WHERE 1=1 {enabled_filter}
        ORDER BY u.domain, u.username
    """
    generate_paginated_pages("policy", "Policy Violations", ["Domain", "Username", "Password", "Reason"], q_pv, q_pv_count)

    # --- High Value Page ---
    hv_placeholders = ','.join('?' * len(high_value_groups))
    hv_params = [g.lower() for g in high_value_groups]
    q_hv_count = f"""
        SELECT COUNT(DISTINCT u.id)
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        JOIN user_groups ug ON u.id = ug.user_id
        WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL
        AND lower(ug.group_name) IN ({hv_placeholders}) {enabled_filter}
    """
    q_hv = f"""
        SELECT DISTINCT u.domain, u.username, {pwd_col}
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        JOIN user_groups ug ON u.id = ug.user_id
        WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL
        AND lower(ug.group_name) IN ({hv_placeholders}) {enabled_filter}
        ORDER BY u.domain, u.username
    """
    generate_paginated_pages("high_value", "High Value Accounts", ["Domain", "Username", "Password"], q_hv, q_hv_count, tuple(hv_params))

    # --- Kerberoastable Page ---
    q_kerb_count = f"SELECT COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL AND u.kerberoastable = 1 {enabled_filter}"
    q_kerb = f"SELECT u.domain, u.username, {pwd_col} FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL AND u.kerberoastable = 1 {enabled_filter} ORDER BY u.domain, u.username"
    generate_paginated_pages("kerberoastable", "Kerberoastable & Cracked", ["Domain", "Username", "Password"], q_kerb, q_kerb_count)

    # --- ASREPRoastable Page ---
    q_asrep_count = f"SELECT COUNT(*) FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL AND u.asreproastable = 1 {enabled_filter}"
    q_asrep = f"SELECT u.domain, u.username, {pwd_col} FROM hashes h JOIN users u ON h.user_id = u.id WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL AND u.asreproastable = 1 {enabled_filter} ORDER BY u.domain, u.username"
    generate_paginated_pages("asreproastable", "ASREPRoastable & Cracked", ["Domain", "Username", "Password"], q_asrep, q_asrep_count)

    # --- Flags Page ---
    q_flags_count = f"SELECT COUNT(*) FROM users u WHERE (u.pwdneverexpires = 1 OR u.passwordnotreqd = 1) {enabled_filter}"
    q_flags = f"""
        SELECT u.domain, u.username,
               CASE WHEN u.pwdneverexpires = 1 THEN 'Yes' ELSE 'No' END,
               CASE WHEN u.passwordnotreqd = 1 THEN 'Yes' ELSE 'No' END
        FROM users u
        WHERE (u.pwdneverexpires = 1 OR u.passwordnotreqd = 1) {enabled_filter}
        ORDER BY u.domain, u.username
    """
    generate_paginated_pages("flags", "Account Flags", ["Domain", "Username", "Password Never Expires", "Password Not Required"], q_flags, q_flags_count)

    # --- History Page ---
    # We find max history dynamically by querying the database for max history hashes for a user
    c.execute(f"SELECT MAX(hist_count) FROM (SELECT user_id, COUNT(*) as hist_count FROM hashes JOIN users u ON user_id = u.id WHERE is_history = 1 {enabled_filter} GROUP BY user_id)")
    row = c.fetchone()
    max_history = row[0] if row and row[0] else 0

    history_headers = ["Domain", "Username", "Current"]
    for i in range(1, max_history + 1):
        history_headers.append(f"History {i}")

    # Generate custom query for history
    q_hist_count = f"SELECT COUNT(DISTINCT u.id) FROM users u WHERE 1=1 {enabled_filter}"
    c.execute(q_hist_count)
    total_users = c.fetchone()[0]
    total_pages = math.ceil(total_users / 1000)

    if total_pages == 0:
        content = f'<div class="card"><h2>Password History</h2><p>No data available.</p></div>'
        write_page("history_1.html", "Password History", content)
    else:
        for page in range(1, total_pages + 1):
            offset = (page - 1) * 1000

            c.execute(f"SELECT id, domain, username FROM users u WHERE 1=1 {enabled_filter} ORDER BY domain, username LIMIT 1000 OFFSET {offset}")
            users_page = c.fetchall()

            user_ids = [u[0] for u in users_page]
            if not user_ids:
                continue

            placeholders = ','.join('?' * len(user_ids))
            # Get current hashes
            c.execute(f"SELECT user_id, {pwd_col} FROM hashes h WHERE is_history = 0 AND user_id IN ({placeholders})", user_ids)
            current_hashes = {r[0]: r[1] for r in c.fetchall()}

            # Get history hashes
            c.execute(f"SELECT user_id, {pwd_col} FROM hashes h WHERE is_history = 1 AND user_id IN ({placeholders}) ORDER BY user_id, id", user_ids)
            hist_hashes = {}
            for r in c.fetchall():
                uid = r[0]
                if uid not in hist_hashes:
                    hist_hashes[uid] = []
                hist_hashes[uid].append(r[1])

            history_rows_html = ""
            for uid, domain, username in users_page:
                e_dom = html.escape(domain)
                e_usr = html.escape(username)

                curr = current_hashes.get(uid, "")
                curr_display = html.escape(curr if curr else "")

                row_html = f"<tr><td>{e_dom}</td><td>{e_usr}</td><td>{curr_display}</td>"

                h_list = hist_hashes.get(uid, [])
                for i in range(max_history):
                    if i < len(h_list):
                        h_val = h_list[i]
                        h_display = html.escape(h_val if h_val else "")
                        row_html += f"<td>{h_display}</td>"
                    else:
                        row_html += "<td></td>"

                row_html += "</tr>"
                history_rows_html += row_html

            table_html = f"""
            <div class="card">
                <h2>User Password History</h2>
                <input type="text" id="histFilter" onkeyup="filterTable('histFilter', 'histTable')" placeholder="Filter by Domain or Username...">
                <table id="histTable">
                    <tr>{"".join(f"<th>{h}</th>" for h in history_headers)}</tr>
                    {history_rows_html}
                </table>
            </div>
            """

            pagination = generate_pagination_html("history", page, total_pages)
            final_content = pagination + table_html + pagination

            write_page(f"history_{page}.html", "Password History", final_content)

    conn.close()
    logging.info(f"Reports generated successfully in directory: {output_dir}/")


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

    metrics = calculate_metrics(db_path, high_value_groups, policy, args.redact, args.enabled_only)
    logging.info("Metrics calculated.")

    generate_html_report(db_path, metrics, high_value_groups, args.redact, args.outdir)

    if os.path.exists(db_path):
        os.remove(db_path)

    logging.info("Analysis complete.")

if __name__ == '__main__':
    main()
