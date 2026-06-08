import time
import tracemalloc

# mock data
users_to_map = [("id1", "SHORT", f"User_{i}") for i in range(1000000)]
domain_mapping = {"short": ["Option1.local", "Option2.local", "Option3.local"]}
existing_ntds_combos = {("option1.local", f"user_{i}") for i in range(1000000)}

def run_original():
    tracemalloc.start()
    start = time.time()
    updates = []
    for user_id, orig_domain, base_username in users_to_map:
        options = domain_mapping[orig_domain.lower()]
        final_domain = orig_domain

        if len(options) > 1:
            found_options = []
            for opt in options:
                if (opt.lower(), base_username.lower()) in existing_ntds_combos:
                    found_options.append(opt)
    duration = time.time() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"Original: {duration:.4f}s")

def run_optimized():
    tracemalloc.start()
    start = time.time()

    # Pre-calculate lowercased options
    mapping_cache = {}
    for dom, opts in domain_mapping.items():
        mapping_cache[dom] = [(opt, opt.lower()) for opt in opts]

    updates = []
    for user_id, orig_domain, base_username in users_to_map:
        orig_domain_lower = orig_domain.lower()
        options_cached = mapping_cache[orig_domain_lower]
        final_domain = orig_domain

        if len(options_cached) > 1:
            found_options = []
            base_username_lower = base_username.lower()
            for opt, opt_lower in options_cached:
                if (opt_lower, base_username_lower) in existing_ntds_combos:
                    found_options.append(opt)
    duration = time.time() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"Optimized: {duration:.4f}s")

run_original()
run_optimized()
