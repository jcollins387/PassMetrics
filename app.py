import sqlite3
from flask import Flask, render_template, request, g

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

    return render_template('dashboard.html',
                           total_accounts=total_accounts,
                           total_passwords=total_passwords,
                           total_cracked=total_cracked)

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
        ORDER BY count DESC
    """)
    lengths_data = c.fetchall()

    return render_template('lengths.html', lengths=lengths_data)

@app.route('/shared')
def shared():
    page = request.args.get('page', 1, type=int)
    per_page = 1000
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

    return render_template('shared.html', shared=shared_data, page=page)

@app.route('/lm_hashes')
def lm_hashes():
    page = request.args.get('page', 1, type=int)
    per_page = 1000
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

    return render_template('lm_hashes.html', users=lm_data, page=page)

@app.route('/policy')
def policy():
    page = request.args.get('page', 1, type=int)
    per_page = 1000
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    c.execute("""
        SELECT u.domain, u.username, pv.reason
        FROM policy_violations pv
        JOIN users u ON pv.user_id = u.id
        ORDER BY u.domain, u.username
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    policy_data = c.fetchall()

    return render_template('policy.html', violations=policy_data, page=page)

@app.route('/high_value')
def high_value():
    import json
    page = request.args.get('page', 1, type=int)
    per_page = 1000
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    c.execute("SELECT value FROM config WHERE key = 'high_value_groups'")
    row = c.fetchone()
    high_value_groups = json.loads(row[0]) if row else []

    hv_data = []
    if high_value_groups:
        placeholders = ','.join('?' * len(high_value_groups))
        params = [g.lower() for g in high_value_groups] + [per_page, offset]

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

    return render_template('high_value.html', users=hv_data, page=page)

@app.route('/kerberoastable')
def kerberoastable():
    page = request.args.get('page', 1, type=int)
    per_page = 1000
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

    return render_template('kerberoastable.html', users=krb_data, page=page)

@app.route('/asreproastable')
def asreproastable():
    page = request.args.get('page', 1, type=int)
    per_page = 1000
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

    return render_template('asreproastable.html', users=asrep_data, page=page)

@app.route('/flags')
def flags():
    page = request.args.get('page', 1, type=int)
    per_page = 1000
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

    return render_template('flags.html', users=flags_data, page=page)

@app.route('/history')
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 1000
    offset = (page - 1) * per_page

    db = get_db()
    c = db.cursor()

    # In SQLite, gathering dynamic history columns per user is complex in a single query.
    # Group concat history hashes for the portal view.
    c.execute("""
        SELECT u.domain, u.username,
               MAX(CASE WHEN h.is_history = 0 THEN h.cracked_password ELSE NULL END) as current_password,
               GROUP_CONCAT(CASE WHEN h.is_history = 1 THEN h.cracked_password ELSE NULL END, ', ') as history_passwords
        FROM users u
        JOIN hashes h ON u.id = h.user_id
        GROUP BY u.id
        HAVING history_passwords IS NOT NULL
        ORDER BY u.domain, u.username
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    history_data = c.fetchall()

    return render_template('history.html', history=history_data, page=page)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
