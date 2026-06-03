import sqlite3
import io
import csv
from flask import Flask, render_template, request, g, Response

app = Flask(__name__)
DATABASE = 'analysis.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.route('/')
def dashboard():
    db = get_db()
    c = db.cursor()

    c.execute("SELECT COUNT(*) FROM users")
    total_accounts = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM hashes WHERE is_history = 0")
    total_passwords = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM hashes WHERE is_history = 0 AND cracked_password IS NOT NULL")
    total_cracked = c.fetchone()[0]

    c.execute("SELECT COUNT(DISTINCT user_id) FROM policy_violations")
    total_policy_violations = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM users WHERE kerberoastable = 1 AND enabled = 1")
    total_kerberoastable = c.fetchone()[0]

    c.execute("""
        SELECT COUNT(*)
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        WHERE u.kerberoastable = 1 AND u.enabled = 1 AND h.is_history = 0 AND h.cracked_password IS NOT NULL
    """)
    cracked_kerberoastable = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM users WHERE asreproastable = 1 AND enabled = 1")
    total_asreproastable = c.fetchone()[0]

    c.execute("""
        SELECT COUNT(*)
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        WHERE u.asreproastable = 1 AND u.enabled = 1 AND h.is_history = 0 AND h.cracked_password IS NOT NULL
    """)
    cracked_asreproastable = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM users WHERE pwdneverexpires = 1")
    total_pwdneverexpires = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM users WHERE passwordnotreqd = 1")
    total_passwordnotreqd = c.fetchone()[0]

    import json
    c.execute("SELECT value FROM config WHERE key = 'high_value_groups'")
    row = c.fetchone()
    high_value_groups = json.loads(row[0]) if row else []

    total_high_value = 0
    cracked_high_value = 0

    if high_value_groups:
        placeholders = ','.join('?' * len(high_value_groups))
        params = [g.lower() for g in high_value_groups]

        c.execute(f"""
            SELECT COUNT(DISTINCT u.id)
            FROM users u
            JOIN user_groups ug ON u.id = ug.user_id
            WHERE lower(ug.group_name) IN ({placeholders})
        """, params)
        total_high_value = c.fetchone()[0]

        c.execute(f"""
            SELECT COUNT(DISTINCT u.id)
            FROM users u
            JOIN hashes h ON u.id = h.user_id
            JOIN user_groups ug ON u.id = ug.user_id
            WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL
            AND lower(ug.group_name) IN ({placeholders})
        """, params)
        cracked_high_value = c.fetchone()[0]

    c.execute("""
        SELECT cracked_password, COUNT(*) as count
        FROM hashes
        WHERE is_history = 0 AND cracked_password IS NOT NULL
        GROUP BY cracked_password
        ORDER BY count DESC
        LIMIT 5
    """)
    top_common = c.fetchall()

    c.execute("""
        SELECT DISTINCT cracked_password, length(cracked_password) as pw_length
        FROM hashes
        WHERE is_history = 0 AND cracked_password IS NOT NULL
        ORDER BY pw_length DESC
        LIMIT 5
    """)
    top_longest = c.fetchall()

    c.execute("""
        SELECT DISTINCT cracked_password, length(cracked_password) as pw_length
        FROM hashes
        WHERE is_history = 0 AND cracked_password IS NOT NULL
        ORDER BY pw_length ASC
        LIMIT 5
    """)
    top_shortest = c.fetchall()

    c.execute("""
        SELECT length(cracked_password) as pw_length, COUNT(*) as count
        FROM hashes
        WHERE is_history = 0 AND cracked_password IS NOT NULL
        GROUP BY length(cracked_password)
        ORDER BY pw_length ASC
    """)
    lengths_data = c.fetchall()
    max_count = max([row["count"] for row in lengths_data]) if lengths_data else 1

    return render_template('dashboard.html',
                           total_accounts=total_accounts,
                           total_passwords=total_passwords,
                           total_cracked=total_cracked,
                           total_policy_violations=total_policy_violations,
                           total_kerberoastable=total_kerberoastable,
                           cracked_kerberoastable=cracked_kerberoastable,
                           total_asreproastable=total_asreproastable,
                           cracked_asreproastable=cracked_asreproastable,
                           total_pwdneverexpires=total_pwdneverexpires,
                           total_passwordnotreqd=total_passwordnotreqd,
                           total_high_value=total_high_value,
                           cracked_high_value=cracked_high_value,
                           top_common=top_common,
                           top_longest=top_longest,
                           top_shortest=top_shortest,
                           lengths=lengths_data,
                           max_count=max_count)



import io
import csv
from flask import Response


@app.route('/export_csv')
def export_csv():
    db = get_db()
    c = db.cursor()

    # Get users and their policy violations
    c.execute('''
        SELECT u.id, u.domain, u.username, u.passwordnotreqd, u.pwdneverexpires, u.kerberoastable, u.asreproastable, pv.reason
        FROM users u
        LEFT JOIN policy_violations pv ON u.id = pv.user_id
        ORDER BY u.domain, u.username
    ''')
    rows = c.fetchall()

    # Find all unique policy violations dynamically based on the reason string
    violation_types = set()
    for row in rows:
        reason = row['reason']
        if reason:
            for r in reason.split(','):
                r = r.strip()
                if r:
                    # e.g., "Length < 8" -> "Length", "Fails complexity" -> "Complexity", "Lifetime > 90 days" -> "Lifetime"
                    # However, to be fully dynamic, we extract the first word or handle known cases if they vary,
                    # but the cleanest dynamic way is to take the whole string if it's unique, or prefix it.
                    # Given the examples: Length < x, Fails complexity, Lifetime > x days
                    # Let's extract the core violation type:
                    if r.lower().startswith('length'):
                        violation_types.add('Length')
                    elif 'complexity' in r.lower():
                        violation_types.add('Complexity')
                    elif r.lower().startswith('lifetime'):
                        violation_types.add('Lifetime')
                    else:
                        violation_types.add(r) # fallback for fully dynamic

    # Ensure consistent ordering
    violation_types = sorted(list(violation_types))

    # Base columns
    headers = [
        'Domain', 'Account Name', 'Password Not Required', 'Password Never Expires',
        'Kerberoastable', 'ASREPRoastable'
    ]

    # Dynamic columns
    for vt in violation_types:
        headers.append(f'Policy Violation - {vt}')

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(headers)

    for row in rows:
        domain = row['domain']
        username = row['username']
        pnr = 'x' if row['passwordnotreqd'] else ''
        pne = 'x' if row['pwdneverexpires'] else ''
        kerb = 'x' if row['kerberoastable'] else ''
        asrep = 'x' if row['asreproastable'] else ''

        csv_row = [domain, username, pnr, pne, kerb, asrep]

        reason = row['reason'] or ''
        reason_list = [r.strip() for r in reason.split(',')] if reason else []

        for vt in violation_types:
            found = False
            for r in reason_list:
                if vt == 'Length' and r.lower().startswith('length'):
                    found = True
                elif vt == 'Complexity' and 'complexity' in r.lower():
                    found = True
                elif vt == 'Lifetime' and r.lower().startswith('lifetime'):
                    found = True
                elif vt == r:
                    found = True

            if found:
                csv_row.append('x')
            else:
                csv_row.append('')

        cw.writerow(csv_row)

    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=report.csv"}
    )

@app.route('/export_reset_csv')
def export_reset_csv():
    db = get_db()
    c = db.cursor()

    c.execute('''
        SELECT u.domain, u.username,
               CASE WHEN h.cracked_password IS NOT NULL THEN 'TRUE' ELSE '' END as needs_reset
        FROM users u
        LEFT JOIN hashes h ON u.id = h.user_id AND h.is_history = 0
        ORDER BY u.domain, u.username
    ''')
    rows = c.fetchall()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Domain', 'Username', 'Needs Reset'])

    for row in rows:
        cw.writerow([row['domain'], row['username'], row['needs_reset']])

    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=accounts_needing_reset.csv"}
    )


@app.route('/export_shared_csv')
def export_shared_csv():
    db = get_db()
    c = db.cursor()

    c.execute('''
        SELECT u.domain, u.username,
               CASE WHEN hc.uses > 1 THEN 'TRUE' ELSE '' END as is_shared,
               IFNULL(hc.uses, 0) as total_uses
        FROM users u
        LEFT JOIN hashes h ON u.id = h.user_id AND h.is_history = 0
        LEFT JOIN (
            SELECT lower(nt_hash) as hash_val, COUNT(*) as uses
            FROM hashes
            WHERE is_history = 0 AND nt_hash IS NOT NULL AND nt_hash != ''
            GROUP BY lower(nt_hash)
        ) hc ON lower(h.nt_hash) = hc.hash_val
        ORDER BY u.domain, u.username
    ''')
    rows = c.fetchall()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Domain', 'Username', 'Shared Hash', 'Total Uses'])

    for row in rows:
        cw.writerow([row['domain'], row['username'], row['is_shared'], row['total_uses'] if row['is_shared'] == 'TRUE' else ''])

    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=shared_passwords.csv"}
    )


@app.route('/export_length_csv')
def export_length_csv():
    db = get_db()
    c = db.cursor()

    c.execute('''
        SELECT u.domain, u.username, pv.reason
        FROM users u
        LEFT JOIN hashes h ON u.id = h.user_id AND h.is_history = 0 AND h.cracked_password IS NOT NULL
        LEFT JOIN policy_violations pv ON u.id = pv.user_id
        WHERE h.id IS NOT NULL
        ORDER BY u.domain, u.username
    ''')
    rows = c.fetchall()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Domain', 'Username', 'Length Violation', 'Requirement'])

    for row in rows:
        domain = row['domain']
        username = row['username']
        reason = row['reason'] or ''
        reason_list = [r.strip() for r in reason.split(',')] if reason else []

        length_req = ''
        is_violation = ''
        for r in reason_list:
            if r.lower().startswith('length'):
                parts = r.split(' ', 1)
                if len(parts) > 1:
                    length_req = parts[1]
                else:
                    length_req = r
                is_violation = 'TRUE'
                break

        cw.writerow([domain, username, is_violation, length_req])

    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=length_violations.csv"}
    )

@app.route('/lengths')
def lengths():
    db = get_db()
    c = db.cursor()

    # Calculate lengths dynamically
    c.execute("""
        SELECT length(cracked_password) as pw_length, COUNT(*) as count
        FROM hashes
        WHERE is_history = 0 AND cracked_password IS NOT NULL
        GROUP BY length(cracked_password)
        ORDER BY pw_length DESC
    """)
    lengths_data = c.fetchall()

    return render_template('lengths.html', lengths=lengths_data)

@app.route('/shared')
def shared():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    c.execute("""
        SELECT lower(h.nt_hash) as nt_hash, h.cracked_password, COUNT(h.id) as count,
               GROUP_CONCAT(u.domain || '\\' || u.username, ', ') as shared_by
        FROM hashes h
        JOIN users u ON h.user_id = u.id
        WHERE h.is_history = 0
        GROUP BY lower(h.nt_hash)
        HAVING COUNT(h.id) > 1
        ORDER BY count DESC
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    shared_data = c.fetchall()

    return render_template('shared.html', shared=shared_data, page=page, per_page=per_page)

@app.route('/lm_hashes')
def lm_hashes():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    c.execute("""
        SELECT u.domain, u.username, h.lm_hash
        FROM hashes h
        JOIN users u ON h.user_id = u.id
        WHERE h.is_history = 0 AND lower(h.lm_hash) != 'aad3b435b51404eeaad3b435b51404ee'
        ORDER BY u.domain, u.username
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    lm_data = c.fetchall()

    return render_template('lm_hashes.html', users=lm_data, page=page, per_page=per_page)

@app.route('/policy')
def policy():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    c.execute("""
        SELECT u.domain, u.username, pv.policy_name, pv.reason
        FROM policy_violations pv
        JOIN users u ON pv.user_id = u.id
        ORDER BY u.domain, u.username
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    policy_data = c.fetchall()

    return render_template('policy.html', violations=policy_data, page=page, per_page=per_page)

@app.route('/high_value')
def high_value():
    import json
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    group_filter = request.args.get('group', 'default')
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    c.execute("SELECT value FROM config WHERE key = 'high_value_groups'")
    row = c.fetchone()
    high_value_groups = json.loads(row[0]) if row else []

    hv_data = []
    if high_value_groups:
        if group_filter == 'all':
            target_groups = high_value_groups
        elif group_filter != 'default':
            target_groups = [group_filter]
        else:
            # Default is Domain Admins and Enterprise Admins if they exist
            target_groups = [g for g in high_value_groups if g.lower() in ('domain admins', 'enterprise admins')]
            if not target_groups:
                target_groups = high_value_groups # fallback to all if defaults aren't there

        placeholders = ','.join('?' * len(target_groups))
        params = [g.lower() for g in target_groups] + [per_page, offset]

        c.execute(f"""
            SELECT DISTINCT u.domain, u.username, ug.group_name, h.cracked_password
            FROM users u
            JOIN hashes h ON u.id = h.user_id
            JOIN user_groups ug ON u.id = ug.user_id
            WHERE h.is_history = 0 AND h.cracked_password IS NOT NULL
            AND lower(ug.group_name) IN ({placeholders})
            ORDER BY u.domain, u.username
            LIMIT ? OFFSET ?
        """, params)
        hv_data = c.fetchall()

    return render_template('high_value.html', users=hv_data, page=page, per_page=per_page, groups=high_value_groups, selected_group=group_filter)

@app.route('/kerberoastable')
def kerberoastable():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    c.execute("""
        SELECT u.domain, u.username, h.cracked_password
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        WHERE h.is_history = 0 AND u.kerberoastable = 1 AND u.enabled = 1
        ORDER BY u.domain, u.username
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    krb_data = c.fetchall()

    return render_template('kerberoastable.html', users=krb_data, page=page, per_page=per_page)

@app.route('/asreproastable')
def asreproastable():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    c.execute("""
        SELECT u.domain, u.username, h.cracked_password
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        WHERE h.is_history = 0 AND u.asreproastable = 1 AND u.enabled = 1
        ORDER BY u.domain, u.username
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    asrep_data = c.fetchall()

    return render_template('asreproastable.html', users=asrep_data, page=page, per_page=per_page)

@app.route('/flags')
def flags():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    c.execute("""
        SELECT domain, username, pwdneverexpires, passwordnotreqd
        FROM users
        WHERE pwdneverexpires = 1 OR passwordnotreqd = 1
        ORDER BY domain, username
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    flags_data = c.fetchall()

    return render_template('flags.html', users=flags_data, page=page, per_page=per_page)

@app.route('/history')
def history():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    # Get users with history
    c.execute("""
        SELECT u.id, u.domain, u.username
        FROM users u
        WHERE EXISTS (SELECT 1 FROM hashes h WHERE h.user_id = u.id AND h.is_history = 1)
        ORDER BY u.domain, u.username
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    users = c.fetchall()

    history_data = []
    max_history = 0

    if users:
        user_ids = [str(u['id']) for u in users]
        placeholders = ','.join(user_ids)
        c.execute(f"""
            SELECT user_id, is_history, cracked_password, id as hash_id
            FROM hashes
            WHERE user_id IN ({placeholders})
            ORDER BY user_id, hash_id ASC
        """)
        hashes = c.fetchall()

        user_dict = {u['id']: {'domain': u['domain'], 'username': u['username'], 'current': '', 'history': []} for u in users}

        for h in hashes:
            uid = h['user_id']
            cp = h['cracked_password'] if h['cracked_password'] is not None else ''
            if h['is_history'] == 0:
                user_dict[uid]['current'] = cp
            else:
                user_dict[uid]['history'].append(cp)

        for uid, data in user_dict.items():
            max_history = max(max_history, len(data['history']))
            history_data.append(data)

    return render_template('history.html', history=history_data, max_history=max_history, page=page, per_page=per_page)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
