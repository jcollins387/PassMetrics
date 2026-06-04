import timeit
import sqlite3
import re

setup_baseline = """
import re
processed_fgpp = [
    {
        'policy': {},
        'match_groups': set(['group1', 'group2', 'group3']),
        'match_ous': ['ou1', 'ou2', 'ou3'],
        'match_usernames': []
    }
] * 10

# Mock rows
rows = [
    (1, 'password', 'group4,group5,group6,group7,group8,group9,group10,group11,group12,group13', 'cn=test,ou=ou10,dc=example,dc=com', 0, 'user1')
] * 1000

def run_baseline():
    for row in rows:
        user_id = row[0]
        pwd = row[1]
        user_groups_lower = row[2].split(",") if row[2] else []
        dn_lower = row[3].lower() if row[3] else ""
        pwdlastset = row[4]
        username = row[5] or ""

        matched_policies = []
        for p in processed_fgpp:
            matched = False

            for g in p['match_groups']:
                if g in user_groups_lower:
                    matched = True
                    break

            if not matched:
                for ou in p['match_ous']:
                    if (dn_lower and ou in dn_lower) or (ou in user_groups_lower):
                        matched = True
                        break
"""

setup_optimized = """
import re
processed_fgpp = [
    {
        'policy': {},
        'match_groups': set(['group1', 'group2', 'group3']),
        'match_ous': ['ou1', 'ou2', 'ou3'],
        'match_usernames': []
    }
] * 10

# Mock rows
rows = [
    (1, 'password', 'group4,group5,group6,group7,group8,group9,group10,group11,group12,group13', 'cn=test,ou=ou10,dc=example,dc=com', 0, 'user1')
] * 1000

def run_optimized():
    for row in rows:
        user_id = row[0]
        pwd = row[1]
        user_groups_lower = set(row[2].split(",")) if row[2] else set()
        dn_lower = row[3].lower() if row[3] else ""
        pwdlastset = row[4]
        username = row[5] or ""

        matched_policies = []
        for p in processed_fgpp:
            matched = False

            for g in p['match_groups']:
                if g in user_groups_lower:
                    matched = True
                    break

            if not matched:
                for ou in p['match_ous']:
                    if (dn_lower and ou in dn_lower) or (ou in user_groups_lower):
                        matched = True
                        break
"""

print(f"Baseline: {timeit.timeit('run_baseline()', setup=setup_baseline, number=1000):.4f}")
print(f"Optimized: {timeit.timeit('run_optimized()', setup=setup_optimized, number=1000):.4f}")
