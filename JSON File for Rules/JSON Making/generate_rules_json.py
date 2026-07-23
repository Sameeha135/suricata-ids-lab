import re
import json
import yaml
import requests
import tarfile
import io

INDEX_URL = "https://www.openinfosecfoundation.org/rules/index.yaml"
OUTPUT_FILE = "suricata_community_sample.json"
SURICATA_VERSION = "8.0.6"

# Set TEST_LIMIT to 10 for testing per source, or None for all rules
TEST_LIMIT = 10

RULE_REGEX = re.compile(
    r"^(?P<action>alert|drop|pass|reject|sdrop|log)\s+"
    r"(?P<protocol>\w+)\s+"
    r"(?P<src_net>\S+)\s+"
    r"(?P<src_port>\S+)\s+"
    r"(?P<direction>->|<-|<>)\s+"
    r"(?P<dst_net>\S+)\s+"
    r"(?P<dst_port>\S+)\s*"
    r"\((?P<body>.*)\)$"
)

SOURCE_METADATA = {
    "abuse.ch/urlhaus": {"vendor": "Abuse.ch", "description": "Identifies traffic to malicious URLs distributing malware"},
    "abuse.ch/feodotracker": {"vendor": "Abuse.ch", "description": "Botnet C2 IP/port indicators (Dridex, TrickBot, QakBot)"},
    "abuse.ch/sslbl-blacklist": {"vendor": "Abuse.ch", "description": "Malicious SSL/TLS certificate detection"},
    "abuse.ch/sslbl-ja3": {"vendor": "Abuse.ch", "description": "JA3 fingerprint detection for malware SSL/TLS"},
    "stamus/lateral": {"vendor": "Stamus Networks", "description": "Lateral movement detection in Windows environments"},
    "tgreen/hunting": {"vendor": "tgreen", "description": "Experimental heuristic threat-hunting rules"},
    "ipfire/dbl": {"vendor": "IPFire", "description": "Malicious/phishing domain blocklist"},
    "julioliraup/antiphishing": {"vendor": "julioliraup", "description": "Phishing/credential-harvesting site detection"},
    "the-hunters-ledger/open": {"vendor": "The Hunter's Ledger", "description": "Signatures from active malware campaign investigations"},
    "pawpatrules": {"vendor": "pawpatrules", "description": "General-purpose community ruleset"},
    "aleksibovellan/nmap": {"vendor": "aleksibovellan", "description": "Nmap scan reconnaissance detection"},
    "etnetera/aggressive": {"vendor": "Etnetera a.s.", "description": "Aggressive/abusive IP blacklist"},
    "oisf/trafficid": {"vendor": "OISF", "description": "Protocol/application traffic classification"},
    "ptrules/open": {"vendor": "Positive Technologies", "description": "CVE exploit and TTP detection"},
}


def fetch_index():
    print("[+] Fetching OISF index.yaml...")
    response = requests.get(INDEX_URL, timeout=15)
    response.raise_for_status()
    return yaml.safe_load(response.text)


def build_download_url(url_template, suricata_version=SURICATA_VERSION):
    """Substitutes version placeholders safely; returns None if source requires a paid secret-code."""
    if not url_template or "secret-code" in url_template:
        return None
    url = url_template.replace("%(__version__)s", suricata_version)
    url = url.replace("%(__conf_version__)s", suricata_version.split(".")[0])
    return url


def get_rule_lines(url):
    """Downloads a rule source, handling both plain .rules files and compressed .tar.gz archives."""
    res = requests.get(url, timeout=25)
    res.raise_for_status()

    if url.endswith(".tar.gz") or url.endswith(".tgz"):
        lines = []
        with tarfile.open(fileobj=io.BytesIO(res.content), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".rules"):
                    f = tar.extractfile(member)
                    if f:
                        lines.extend(f.read().decode("utf-8", errors="ignore").splitlines())
        return lines
    else:
        return res.text.splitlines()


def parse_rule_line(line, source_name):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    match = RULE_REGEX.match(line)
    if not match:
        return None

    header = match.groupdict()
    body_str = header.pop("body")

    # Core options extraction
    msg_match = re.search(r'msg:\s*"(.*?)"\s*;', body_str)
    sid_match = re.search(r'sid:\s*(\d+)\s*;', body_str)
    rev_match = re.search(r'rev:\s*(\d+)\s*;', body_str)
    classtype_match = re.search(r'classtype:\s*([^;]+)\s*;', body_str)
    
    # Extended options extraction
    flow_match = re.search(r'flow:\s*([^;]+)\s*;', body_str)
    flowbits_match = re.search(r'flowbits:\s*([^;]+)\s*;', body_str)
    reference_matches = re.findall(r'reference:\s*([^;]+)\s*;', body_str)
    metadata_match = re.search(r'metadata:\s*([^;]+(?:\s*;\s*[^;]+)*)\s*;', body_str)

    meta = SOURCE_METADATA.get(source_name, {"vendor": "Unknown", "description": ""})

    # Ordered dictionary ensuring shared structural fields are grouped consistently first
    return {
        "sid": int(sid_match.group(1)) if sid_match else None,
        "rev": int(rev_match.group(1)) if rev_match else None,
        "msg": msg_match.group(1) if msg_match else "No description",
        "classtype": classtype_match.group(1).strip() if classtype_match else "unknown",
        "action": header["action"],
        "protocol": header["protocol"],
        "src_net": header["src_net"],
        "src_port": header["src_port"],
        "direction": header["direction"],
        "dst_net": header["dst_net"],
        "dst_port": header["dst_port"],
        "ruleset": source_name,
        "vendor": meta["vendor"],
        "flow": flow_match.group(1).strip() if flow_match else None,
        "flowbits": flowbits_match.group(1).strip() if flowbits_match else None,
        "references": [ref.strip() for ref in reference_matches] if reference_matches else [],
        "rule_metadata": metadata_match.group(1).strip() if metadata_match else None,
        "source_description": meta["description"],
        "raw_rule": line
    }


def main():
    index_data = fetch_index()
    sources = index_data.get("sources", {})

    print(f"[+] Debug - sources type: {type(sources)}")
    if isinstance(sources, dict):
        print(f"[+] Debug - sample keys: {list(sources.keys())[:5]}")
    else:
        print("[!] Warning: sources is not a dictionary!")

    parsed_rules = []
    target_sources = set(SOURCE_METADATA.keys())
    found_sources = set()

    for name, source in sources.items():
        if name not in target_sources:
            continue

        found_sources.add(name)
        url_template = source.get("url")
        url = build_download_url(url_template)

        if not url:
            print(f"[-] Skipping commercial/restricted source: {name}")
            continue

        print(f"[+] Processing source: {name} -> {url}")
        try:
            lines = get_rule_lines(url)
            count = 0
            for line in lines:
                rule_obj = parse_rule_line(line, source_name=name)
                if rule_obj:
                    parsed_rules.append(rule_obj)
                    count += 1
                    if TEST_LIMIT and count >= TEST_LIMIT:
                        break
            print(f"    [->] Captured {count} sample rules from {name}")

        except Exception as e:
            print(f"    [!] Error downloading {name}: {e}")

    missing = target_sources - found_sources
    if missing:
        print(f"[!] WARNING: These target sources were NOT found in the index: {missing}")
    else:
        print("[+] All target sources matched successfully against the index keys.")

    print(f"[+] Writing {len(parsed_rules)} total sample rules to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(parsed_rules, f, indent=2, ensure_ascii=False)

    print("[+] Complete!")


if __name__ == "__main__":
    main()