import time
import random

def baseline(rows):
    violation_types = set()
    unique_reasons = {row['reason'] for row in rows if row['reason']}
    for reason in unique_reasons:
        for r in reason.split(','):
            r = r.strip()
            if r:
                r_lower = r.lower()
                if r_lower.startswith('length'):
                    violation_types.add('Length')
                elif 'complexity' in r_lower:
                    violation_types.add('Complexity')
                elif r_lower.startswith('lifetime'):
                    violation_types.add('Lifetime')
                else:
                    violation_types.add(r)

    violation_types = sorted(list(violation_types))

    out = []
    for row in rows:
        reason = row['reason'] or ''
        reason_list = [r.strip() for r in reason.split(',')] if reason else []

        row_violation_types = set()
        for r in reason_list:
            r_lower = r.lower()
            if r_lower.startswith('length'):
                row_violation_types.add('Length')
            if 'complexity' in r_lower:
                row_violation_types.add('Complexity')
            if r_lower.startswith('lifetime'):
                row_violation_types.add('Lifetime')
            row_violation_types.add(r)

        row_out = []
        for vt in violation_types:
            if vt in row_violation_types:
                row_out.append('x')
            else:
                row_out.append('')
        out.append(row_out)
    return out

def optimized(rows):
    parsed_reasons = {}
    violation_types = set()

    unique_reasons = {row['reason'] for row in rows if row['reason']}
    for reason in unique_reasons:
        types = set()
        for r in reason.split(','):
            r = r.strip()
            if not r:
                continue
            r_lower = r.lower()
            if r_lower.startswith('length'):
                types.add('Length')
            elif 'complexity' in r_lower:
                types.add('Complexity')
            elif r_lower.startswith('lifetime'):
                types.add('Lifetime')
            else:
                types.add(r)
        parsed_reasons[reason] = types
        violation_types.update(types)

    violation_types = sorted(list(violation_types))

    out = []
    for row in rows:
        reason = row['reason']
        row_violation_types = parsed_reasons.get(reason, set())

        row_out = []
        for vt in violation_types:
            if vt in row_violation_types:
                row_out.append('x')
            else:
                row_out.append('')
        out.append(row_out)
    return out

# generate rows
random.seed(42)
reasons_pool = [
    "Length < 8",
    "Fails complexity",
    "Lifetime > 90 days",
    "Length < 8, Fails complexity",
    "Length < 8, Lifetime > 90 days",
    "Fails complexity, Lifetime > 90 days",
    "Length < 8, Fails complexity, Lifetime > 90 days",
    "Custom violation",
    "",
    None
]
rows = [{'reason': random.choice(reasons_pool)} for _ in range(100000)]

start = time.time()
baseline_res = baseline(rows)
base_time = time.time() - start
print(f"Baseline: {base_time:.4f}s")

start = time.time()
optimized_res = optimized(rows)
opt_time = time.time() - start
print(f"Optimized: {opt_time:.4f}s")
print(f"Improvement: {base_time/opt_time:.2f}x")
print(f"Results match: {baseline_res == optimized_res}")
