import json
import re

print("[+] Starting SID recovery & merge process...")

# 1. Load the valid backup as our starting base
results = {}
try:
    with open("et_checkpoint_backup.json", "r", encoding="utf-8") as f:
        results = json.load(f)
    print(f"[+] Loaded {len(results)} base rules from et_checkpoint_backup.json")
except Exception as e:
    print(f"[!] Could not load backup: {e}")

# 2. Extract all valid SID records from the corrupt 66.2 MB checkpoint
recovered_count = 0
try:
    with open("et_checkpoint.json", "rb") as f:
        raw_bytes = f.read()

    # Strip leading NULL bytes (common Windows file allocation artifact)
    raw_bytes = raw_bytes.lstrip(b"\x00")
    text = raw_bytes.decode("utf-8", errors="ignore")

    # Regex matches `"SID_NUMBER": { ... rule object ... }`
    pattern = re.compile(r'"(\d+)":\s*(\{(?:[^{}]|\{[^{}]*\})*\})')
    matches = pattern.findall(text)

    for sid_str, json_str in matches:
        if sid_str not in results:
            try:
                rule_obj = json.loads(json_str)
                results[sid_str] = rule_obj
                recovered_count += 1
            except Exception:
                pass

    print(f"[+] Recovered {recovered_count} NEW SIDs from the corrupt 66.2MB file!")
    print(f"[+] Total combined dataset is now: {len(results)} rules.")

    # 3. Save clean merged checkpoint
    with open("et_checkpoint.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False)
    
    print("[+] Successfully updated et_checkpoint.json with merged data!")

except Exception as e:
    print(f"[!] Error during recovery: {e}")