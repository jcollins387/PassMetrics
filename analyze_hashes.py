import argparse
import sys
import json
import logging
import html
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

def parse_args():
    parser = argparse.ArgumentParser(description="Analyze NTDS hashes against a potfile and optional Bloodhound data.")

    parser.add_argument('--ntds', required=True, help="NTDS file containing password hashes")
    parser.add_argument('--potfile', required=True, help="Hashcat potfile containing the cracked hashes")
    parser.add_argument('--bloodhound', nargs='+', help="(OPTIONAL) One or more json files generated from bloodhound")
    parser.add_argument('--policy', help="(OPTIONAL) JSON file containing password policy")
    parser.add_argument('--high-value', help="(OPTIONAL) File containing high value groups/OUs")
    parser.add_argument('--enabled-only', action='store_true', help="(OPTIONAL) Show only 'enabled' users (IGNORE IF NO BLOODHOUND)")
    parser.add_argument('--redact', action='store_true', help="(OPTIONAL) Redact the passwords and hashes in reports")

    return parser.parse_args()

def parse_potfile(potfile_path: str) -> Dict[str, str]:
    """Returns a dict mapping NTHash (lowercase) to cracked password."""
    cracked = {}
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
                    cracked[h.lower()] = p
    return cracked

def parse_ntds(ntds_path: str, cracked: Dict[str, str]) -> Dict[str, UserData]:
    """Parses NTDS dump, skips krbtgt/machine accounts, returns dict mapped by domain\\username."""
    users: Dict[str, UserData] = {}
    logging.info(f"Parsing NTDS file: {ntds_path}")
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

            if key not in users:
                users[key] = UserData(domain=domain, username=base_username, rid=rid)

            # Check if this hash is cracked
            cracked_pass = cracked.get(nt_hash.lower())

            hdata = HashData(lm_hash=lm_hash, nt_hash=nt_hash, is_history=is_history, cracked_password=cracked_pass)
            users[key].hashes.append(hdata)

    return users

def parse_bloodhound(bh_files: List[str], users: Dict[str, UserData]):
    """Parses bloodhound users JSON and group memberships."""
    # Pre-compute username fallback index to avoid O(N^2) lookups
    fallback_index = {}
    for k in users.keys():
        parts = k.split('\\')
        if len(parts) > 1:
            fallback_index[parts[1].lower()] = k

    for bh_file in bh_files:
        logging.info(f"Parsing Bloodhound file: {bh_file}")
        with open(bh_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                logging.error(f"Failed to parse Bloodhound file {bh_file}")
                continue

            if 'data' not in data:
                continue

            total_items = len(data['data'])
            for i, item in enumerate(data['data']):
                if (i + 1) % 10000 == 0:
                    logging.info(f"Processed {i + 1}/{total_items} items from {bh_file}...")

                item_type = item.get('type', item.get('Type', '')).upper()
                props = item.get('Properties', {})

                if item_type == 'USER' or (not item_type and props.get('samaccountname')):
                    domain = props.get('domain', '').split('.')[0] # Try to match short name
                    samaccountname = props.get('samaccountname', '')
                    if not samaccountname:
                        continue

                    key = f"{domain}\\{samaccountname}".lower()

                    # Check if we have this user from NTDS
                    matched_user = users.get(key)
                    if not matched_user:
                        fallback_key = fallback_index.get(samaccountname.lower())
                        if fallback_key:
                            matched_user = users.get(fallback_key)

                    if matched_user:
                        matched_user.enabled = props.get('enabled', True)
                        matched_user.pwdneverexpires = props.get('pwdneverexpires', False)
                        matched_user.passwordnotreqd = props.get('passwordnotreqd', False)
                        matched_user.kerberoastable = props.get('hasspn', False)
                        matched_user.asreproastable = props.get('dontreqpreauth', False)

                # Groups might contain memberships in "Members" array
                if item_type == 'GROUP' or (not item_type and 'Members' in item):
                    group_name = props.get('name', '').split('@')[0] if props.get('name') else ''
                    for member in item.get('Members', []):
                        m_type = member.get('ObjectType', member.get('type', '')).upper()
                        if m_type == 'USER':
                            m_name = member.get('ObjectName', member.get('name', ''))
                            if m_name:
                                m_parts = m_name.split('@')
                                m_user = m_parts[0]
                                m_dom = m_parts[1].split('.')[0] if len(m_parts) > 1 else ''

                                u_key = f"{m_dom}\\{m_user}".lower()
                                matched = users.get(u_key)
                                if not matched:
                                    fallback_key = fallback_index.get(m_user.lower())
                                    if fallback_key:
                                        matched = users.get(fallback_key)
                                if matched and group_name:
                                    matched.groups.add(group_name)

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

def calculate_metrics(users: Dict[str, UserData], high_value_groups: List[str], policy: Dict, redact: bool, enabled_only: bool) -> Dict:
    metrics = {
        'total_accounts': 0,
        'kerberoastable_cracked': [],
        'asreproastable_cracked': [],
        'high_value_cracked': [],
        'policy_violations': [],
        'unique_passwords': set(),
        'unique_cracked': set(),
        'total_passwords': 0,
        'total_cracked': 0,
        'lm_hashes': [],
        'shared_passwords': {}, # mapping of nt_hash -> list of users
        'pwdneverexpires': [],
        'passwordnotreqd': [],
        'password_lengths': {},
        'enabled_only_flag': enabled_only
    }

    # Pre-filter accounts
    active_users = []
    for key, user in users.items():
        if enabled_only and not user.enabled:
            continue
        active_users.append(user)

    metrics['total_accounts'] = len(active_users)
    logging.info(f"Calculating metrics for {len(active_users)} active users...")

    for i, user in enumerate(active_users):
        if (i + 1) % 10000 == 0:
            logging.info(f"Calculated metrics for {i + 1}/{len(active_users)} users...")

        current_hash = user.current_hash
        if not current_hash:
            continue

        # Optional redaction
        if redact and current_hash.cracked_password:
            current_hash.redacted_password = redact_string(current_hash.cracked_password)

        # We process based on the current hash

        # Kerberoastable/ASREPRoastable
        if user.kerberoastable and current_hash.cracked_password:
            metrics['kerberoastable_cracked'].append(user)
        if user.asreproastable and current_hash.cracked_password:
            metrics['asreproastable_cracked'].append(user)

        # High value targets
        # Assuming for now bloodhound might populate user.groups, but we check if they are in the lists
        is_high_value = False
        for grp in user.groups:
            if grp in high_value_groups:
                is_high_value = True
                break
        # Fallback if no bloodhound groups are parsed but we want to simulate or check
        # In a real scenario we'd need full group resolution. We'll mark them if they match.
        if is_high_value and current_hash.cracked_password:
            metrics['high_value_cracked'].append(user)

        # Totals and Uniques
        metrics['total_passwords'] += 1
        metrics['unique_passwords'].add(current_hash.nt_hash.lower())

        if current_hash.cracked_password:
            metrics['total_cracked'] += 1
            metrics['unique_cracked'].add(current_hash.cracked_password)

            # Length distribution
            pw_len = len(current_hash.cracked_password)
            metrics['password_lengths'][pw_len] = metrics['password_lengths'].get(pw_len, 0) + 1

            # Policy Violations
            # Find applicable policy
            applicable_policy = policy.get('base', {})
            fgpp_policies = policy.get('fgpp', {})

            # Check for FGPP matching user's groups
            for group, g_policy in fgpp_policies.items():
                if group in user.groups:
                    applicable_policy = g_policy
                    break

            if applicable_policy:
                min_len = applicable_policy.get('length', 0)
                req_complexity = applicable_policy.get('complexity', False)
                # lifetime is harder to check purely statically without dates, but we can report if length or complexity fails

                reasons = []
                if pw_len < min_len:
                    reasons.append(f"Length < {min_len}")

                if req_complexity:
                    has_upper = any(c.isupper() for c in current_hash.cracked_password)
                    has_lower = any(c.islower() for c in current_hash.cracked_password)
                    has_digit = any(c.isdigit() for c in current_hash.cracked_password)
                    has_special = any(not c.isalnum() for c in current_hash.cracked_password)
                    complexity_score = sum([has_upper, has_lower, has_digit, has_special])
                    if complexity_score < 3: # Standard AD complexity rule
                        reasons.append("Fails complexity")

                if reasons:
                    metrics['policy_violations'].append({'user': user, 'reason': ", ".join(reasons)})

        # LM Hashes (Blank LM hash is aad3b435b51404eeaad3b435b51404ee)
        if current_hash.lm_hash.lower() != 'aad3b435b51404eeaad3b435b51404ee':
            metrics['lm_hashes'].append(user)

        # Shared Passwords
        if current_hash.nt_hash.lower() not in metrics['shared_passwords']:
            metrics['shared_passwords'][current_hash.nt_hash.lower()] = []
        metrics['shared_passwords'][current_hash.nt_hash.lower()].append(user)

        # Flags
        if user.pwdneverexpires:
            metrics['pwdneverexpires'].append(user)
        if user.passwordnotreqd:
            metrics['passwordnotreqd'].append(user)

    # Filter shared passwords to only those with >1 user
    shared = {h: u_list for h, u_list in metrics['shared_passwords'].items() if len(u_list) > 1}
    metrics['shared_passwords'] = shared

    return metrics

def generate_html_report(metrics: Dict, users: Dict[str, UserData], redact: bool, output_file: str = "report.html"):
    html_template = """<!DOCTYPE html>
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
</style>
<script>
    function filterTable(inputId, tableId) {{
        var input, filter, table, tr, td, i, j, txtValue;
        input = document.getElementById(inputId);
        filter = input.value.toUpperCase();
        table = document.getElementById(tableId);
        tr = table.getElementsByTagName("tr");
        for (i = 1; i < tr.length; i++) {{
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
</script>
</head>
<body>
    <h1>Password Analysis Report</h1>

    <div class="card">
        <h2>Summary Metrics</h2>
        <p>Total Evaluated Accounts: <span class="metric">{total_accounts}</span></p>
        <p>Total Passwords: {total_passwords} | Total Cracked: <span class="metric">{total_cracked}</span></p>
        <p>Unique Passwords: {unique_passwords} | Unique Cracked: <span class="metric">{unique_cracked}</span></p>
        <p>Kerberoastable & Cracked: <span class="metric">{kerb_cracked}</span></p>
        <p>ASREPRoastable & Cracked: <span class="metric">{asrep_cracked}</span></p>
        <p>High Value Accounts Cracked: <span class="metric">{high_val_cracked}</span></p>
        <p>Accounts with Password Not Required: <span class="metric">{pwd_not_req}</span></p>
        <p>Accounts with Password Never Expires: <span class="metric">{pwd_never_exp}</span></p>
        <p>Accounts with LM Hashes: <span class="metric">{lm_hashes_count}</span></p>
        <p>Accounts Sharing Passwords: <span class="metric">{shared_count}</span></p>
        <p>Accounts with Policy Violations: <span class="metric">{policy_violations_count}</span></p>
    </div>

    <div class="card">
        <h2>Password Length Distribution</h2>
        <div class="bar-chart">
            {length_bars}
        </div>
    </div>

    {tables_html}

    <div class="card">
        <h2>User Password History</h2>
        <input type="text" id="histFilter" onkeyup="filterTable('histFilter', 'histTable')" placeholder="Filter by Domain or Username...">
        <table id="histTable">
            <tr><th>Domain</th><th>Username</th><th>NT Hash</th><th>Cracked Password</th><th>Is History</th></tr>
            {history_rows}
        </table>
    </div>

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

    def get_pwd_display(user):
        h = user.current_hash
        if not h or not h.cracked_password:
            return ""
        return h.redacted_password if redact else h.cracked_password

    def get_hash_display(h_str):
        if not h_str:
            return ""
        return redact_string(h_str) if redact else h_str

    # Helper to generate tables
    def generate_table(title, table_id, headers, rows):
        if not rows:
            return ""
        table_html = f'<div class="card"><h2>{title}</h2>'
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
        return table_html

    tables_html = ""

    # Shared Passwords
    shared_rows = []
    for nt_hash, user_list in metrics['shared_passwords'].items():
        for u in user_list:
            shared_rows.append([u.domain, u.username, get_pwd_display(u)])
    tables_html += generate_table("Shared Passwords", "sharedTable", ["Domain", "Username", "Password"], shared_rows)

    # LM Hashes
    lm_rows = [[u.domain, u.username, get_hash_display(u.current_hash.lm_hash)] for u in metrics['lm_hashes']]
    tables_html += generate_table("Accounts with LM Hashes", "lmTable", ["Domain", "Username", "LM Hash"], lm_rows)

    # Policy Violations
    pv_rows = [[item['user'].domain, item['user'].username, get_pwd_display(item['user']), item['reason']] for item in metrics['policy_violations']]
    tables_html += generate_table("Policy Violations", "pvTable", ["Domain", "Username", "Password", "Reason"], pv_rows)

    # High Value Cracked
    hvc_rows = [[u.domain, u.username, get_pwd_display(u)] for u in metrics['high_value_cracked']]
    tables_html += generate_table("High Value Accounts Cracked", "hvcTable", ["Domain", "Username", "Password"], hvc_rows)

    # Kerberoastable Cracked
    kc_rows = [[u.domain, u.username, get_pwd_display(u)] for u in metrics['kerberoastable_cracked']]
    tables_html += generate_table("Kerberoastable & Cracked", "kcTable", ["Domain", "Username", "Password"], kc_rows)

    # ASREPRoastable Cracked
    ac_rows = [[u.domain, u.username, get_pwd_display(u)] for u in metrics['asreproastable_cracked']]
    tables_html += generate_table("ASREPRoastable & Cracked", "acTable", ["Domain", "Username", "Password"], ac_rows)

    # Flags
    pne_rows = [[u.domain, u.username] for u in metrics['pwdneverexpires']]
    tables_html += generate_table("Password Never Expires", "pneTable", ["Domain", "Username"], pne_rows)
    pnr_rows = [[u.domain, u.username] for u in metrics['passwordnotreqd']]
    tables_html += generate_table("Password Not Required", "pnrTable", ["Domain", "Username"], pnr_rows)

    # History Table
    history_rows = ""

    # Pre-filter accounts for history to respect enabled_only flag if metrics has active accounts conceptually
    # but metrics function didn't return active_users. We can determine it here or pass it.
    for key, user in users.items():
        if metrics.get('enabled_only_flag') and not user.enabled:
            continue

        for h in user.hashes:
            # When redacting history hashes, we need to redact explicitly since we might not have run redact_string on history hashes in metrics calc
            if redact and h.cracked_password:
                display_pwd = redact_string(h.cracked_password)
            else:
                display_pwd = h.cracked_password
            e_dom = html.escape(user.domain)
            e_usr = html.escape(user.username)
            e_hash = html.escape(get_hash_display(h.nt_hash))
            e_pwd = html.escape(display_pwd or '')
            history_rows += f"<tr><td>{e_dom}</td><td>{e_usr}</td><td>{e_hash}</td><td>{e_pwd}</td><td>{'Yes' if h.is_history else 'No'}</td></tr>"

    shared_count = sum(len(u_list) for u_list in metrics['shared_passwords'].values())

    final_html = html_template.format(
        total_accounts=metrics['total_accounts'],
        total_passwords=metrics['total_passwords'],
        total_cracked=metrics['total_cracked'],
        unique_passwords=len(metrics['unique_passwords']),
        unique_cracked=len(metrics['unique_cracked']),
        kerb_cracked=len(metrics['kerberoastable_cracked']),
        asrep_cracked=len(metrics['asreproastable_cracked']),
        high_val_cracked=len(metrics['high_value_cracked']),
        pwd_not_req=len(metrics['passwordnotreqd']),
        pwd_never_exp=len(metrics['pwdneverexpires']),
        lm_hashes_count=len(metrics['lm_hashes']),
        shared_count=shared_count,
        policy_violations_count=len(metrics['policy_violations']),
        length_bars=bars_html,
        tables_html=tables_html,
        history_rows=history_rows
    )

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(final_html)
    logging.info(f"Report generated successfully: {output_file}")


def main():
    args = parse_args()
    logging.info("Starting analysis...")

    cracked = parse_potfile(args.potfile)
    logging.info(f"Loaded {len(cracked)} cracked hashes from potfile.")

    users = parse_ntds(args.ntds, cracked)
    logging.info(f"Parsed {len(users)} users from NTDS.")

    if args.bloodhound:
        parse_bloodhound(args.bloodhound, users)
        logging.info("Parsed Bloodhound data.")

    high_value_groups = parse_high_value(args.high_value)
    policy = parse_policy(args.policy)

    metrics = calculate_metrics(users, high_value_groups, policy, args.redact, args.enabled_only)
    logging.info("Metrics calculated.")

    generate_html_report(metrics, users, args.redact)

if __name__ == '__main__':
    main()
