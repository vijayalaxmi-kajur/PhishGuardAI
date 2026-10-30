import hashlib
import json

with open("scratch/pre_phase15b_hashes.json", "r") as f:
    orig = json.load(f)

all_match = True
for name, meta in orig.items():
    rel_path = meta["path"]
    expected = meta["sha256"]
    with open(rel_path, "rb") as f:
        curr = hashlib.sha256(f.read()).hexdigest()
    match = (curr == expected)
    if not match:
        all_match = False
    print(f"{name} ({rel_path}): {'MATCH' if match else 'FAILED MISMATCH'}")
    if not match:
        print(f"  Expected: {expected}")
        print(f"  Actual:   {curr}")

print(f"\nOVERALL RESULT: {'ALL 7 MATCH' if all_match else 'MISMATCH DETECTED'}")
