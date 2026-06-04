import timeit

setup = """
dn_lower = "cn=test,ou=testou,dc=example,dc=com"
user_groups_lower = ["group1", "group2", "group3", "group4", "group5", "group6", "group7", "group8", "group9", "group10"]
match_ous = ["ou1", "ou2", "ou3", "ou4", "ou5", "testou", "ou6", "ou7", "ou8", "ou9"]
"""

code_baseline = """
matched = False
for ou in match_ous:
    if (dn_lower and ou in dn_lower) or (ou in user_groups_lower):
        matched = True
        break
"""

code_optimized = """
matched = False
user_groups_set = set(user_groups_lower)
for ou in match_ous:
    if (dn_lower and ou in dn_lower) or (ou in user_groups_set):
        matched = True
        break
"""

print(f"Baseline: {timeit.timeit(code_baseline, setup=setup, number=1000000):.6f}")
print(f"Optimized: {timeit.timeit(code_optimized, setup=setup, number=1000000):.6f}")
