import json
import os

MAP_FILE = "sid-msg.map"
CHECKPOINT_FILE = "et_checkpoint.json"
OUTPUT_FILE = "suricata_et_rules.json"
FAILED_SIDS_FILE = "failed_sids.json"
START_INDEX = 0
END_INDEX = 70991


def load_sids_from_map(file_path):
    sids = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("||")
            if len(parts) >= 2:
                try:
                    sids.append(int(parts[0].strip()))
                except ValueError:
                    continue
    return sids


def main():
    if not os.path.exists(MAP_FILE):
        print(f"[!] {MAP_FILE} not found in this directory.")
        return

    all_sids = load_sids_from_map(MAP_FILE)
    print(f"[+] Total SIDs in {MAP_FILE}: {len(all_sids)}")

    target_sids = set(str(s) for s in all_sids[START_INDEX:END_INDEX])
    print(f"[+] SIDs in configured range [{START_INDEX}:{END_INDEX}]: {len(target_sids)}")

    results = {}
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            results = json.load(f)
    scraped_sids = {sid for sid, val in results.items() if val is not None}
    print(f"[+] SIDs with real data in {CHECKPOINT_FILE}: {len(scraped_sids)}")

    failed_sids = set()
    if os.path.exists(FAILED_SIDS_FILE):
        with open(FAILED_SIDS_FILE, "r", encoding="utf-8") as f:
            failed_sids = set(json.load(f))
    print(f"[+] SIDs in {FAILED_SIDS_FILE}: {len(failed_sids)}")

    accounted_for = scraped_sids | failed_sids
    missing = target_sids - accounted_for
    stale_failed = failed_sids & scraped_sids  # failed but actually already scraped

    print("\n" + "=" * 60)
    print(f"Accounted for (scraped + failed): {len(accounted_for)} / {len(target_sids)}")
    if stale_failed:
        print(f"[!] {len(stale_failed)} SIDs are in failed_sids.json AND already scraped — run reconciliation again.")
    if missing:
        print(f"[!] {len(missing)} SIDs are in range but appear in NEITHER file — not accounted for at all.")
        sample = list(missing)[:20]
        print(f"    Sample: {sample}")
    else:
        print("[OK] Every SID in the target range is either scraped or logged as failed.")
    print("=" * 60)

    # --- Now actually check suricata_et_rules.json too, not just the checkpoint ---
    print(f"\n[+] Cross-checking {OUTPUT_FILE} against {CHECKPOINT_FILE}...")
    if not os.path.exists(OUTPUT_FILE):
        print(f"[!] {OUTPUT_FILE} not found — cannot verify it.")
        return

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        output_records = json.load(f)
    print(f"[+] Records in {OUTPUT_FILE}: {len(output_records)}")

    output_sids = {str(r.get("sid")) for r in output_records if r.get("sid") is not None}
    checkpoint_sids = set(results.keys())

    print("\n" + "=" * 60)
    if len(output_records) != len(checkpoint_sids):
        print(f"[!] COUNT MISMATCH: {OUTPUT_FILE} has {len(output_records)} records, "
              f"{CHECKPOINT_FILE} has {len(checkpoint_sids)} keys.")
    else:
        print(f"[OK] Record counts match: {len(output_records)} in both files.")

    only_in_checkpoint = checkpoint_sids - output_sids
    only_in_output = output_sids - checkpoint_sids
    if only_in_checkpoint:
        print(f"[!] {len(only_in_checkpoint)} SIDs are in {CHECKPOINT_FILE} but missing from {OUTPUT_FILE}.")
        print(f"    Sample: {list(only_in_checkpoint)[:10]}")
    if only_in_output:
        print(f"[!] {len(only_in_output)} SIDs are in {OUTPUT_FILE} but missing from {CHECKPOINT_FILE}.")
        print(f"    Sample: {list(only_in_output)[:10]}")
    if not only_in_checkpoint and not only_in_output:
        print(f"[OK] {OUTPUT_FILE} and {CHECKPOINT_FILE} contain the exact same set of SIDs.")

    # Spot-check that content actually matches too, not just SID presence
    output_by_sid = {str(r.get("sid")): r for r in output_records}
    mismatched_content = 0
    for sid in list(checkpoint_sids & output_sids)[:500]:  # sample 500 for speed
        if results.get(sid) != output_by_sid.get(sid):
            mismatched_content += 1
    if mismatched_content:
        print(f"[!] {mismatched_content} sampled records differ in content between the two files.")
    else:
        print("[OK] Sampled records match in content between both files.")
    print("=" * 60)


if __name__ == "__main__":
    main()