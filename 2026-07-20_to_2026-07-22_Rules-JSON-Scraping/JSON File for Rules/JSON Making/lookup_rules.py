import json
import sys
import os

INPUT_FILE = "suricata_et_rules.json"


def load_records():
    if not os.path.exists(INPUT_FILE):
        print(f"[!] {INPUT_FILE} not found in this directory.")
        sys.exit(1)
    print(f"[+] Loading {INPUT_FILE} into memory (one-time load)...")
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def print_record(rec):
    print(json.dumps(rec, indent=2, ensure_ascii=False))
    print("-" * 60)


def main():
    records = load_records()
    print(f"[+] Loaded {len(records)} records. Ready.\n")
    print("Commands:")
    print("  sid <number>        - show one rule by SID")
    print("  msg <keyword>       - search msg field (case-insensitive)")
    print("  category <name>     - filter by category")
    print("  count                - show total record count")
    print("  quit                - exit\n")

    by_sid = {str(r.get("sid")): r for r in records}

    while True:
        try:
            cmd = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not cmd:
            continue
        if cmd in ("quit", "exit"):
            break
        if cmd == "count":
            print(f"Total records: {len(records)}")
            continue

        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            print("Usage: sid <number> | msg <keyword> | category <name>")
            continue

        action, arg = parts[0].lower(), parts[1].strip()

        if action == "sid":
            rec = by_sid.get(arg)
            if rec:
                print_record(rec)
            else:
                print(f"No record found for SID {arg}")

        elif action == "msg":
            matches = [r for r in records if r.get("msg") and arg.lower() in r["msg"].lower()]
            print(f"[{len(matches)} matches]")
            for r in matches[:10]:
                print_record(r)
            if len(matches) > 10:
                print(f"...and {len(matches) - 10} more (refine your search)")

        elif action == "category":
            matches = [r for r in records if r.get("category") and r["category"].lower() == arg.lower()]
            print(f"[{len(matches)} matches]")
            for r in matches[:10]:
                print_record(r)
            if len(matches) > 10:
                print(f"...and {len(matches) - 10} more (refine your search)")

        else:
            print("Unknown command.")


if __name__ == "__main__":
    main()