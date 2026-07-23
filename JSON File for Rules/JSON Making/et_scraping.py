import os
import time
import json
import re
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

# --- Configuration ---
MAP_FILE = "sid-msg.map"
OUTPUT_FILE = "suricata_et_rules.json"
CHECKPOINT_FILE = "et_checkpoint.json"

# Set TEST_LIMIT to None to process all rules in the map file.
TEST_LIMIT = 10

# Rate limit delay in seconds between requests
REQUEST_DELAY = 2


def load_sids_from_map(file_path):
    # Parses sid-msg.map and extracts SID and msg for every rule
    sids = []
    print(f"[+] Loading SIDs from {file_path}...")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Could not find {file_path}. Place it in the script directory.")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split("||")
            if len(parts) >= 2:
                try:
                    sid = int(parts[0].strip())
                    msg = parts[1].strip()
                    sids.append({"sid": sid, "msg": msg})
                except ValueError:
                    continue

    print(f"[+] Found {len(sids)} total rules in {file_path}.")
    return sids


def clean_value(val):
    # Normalizes 'Not Applicable' or empty placeholders to None (null in JSON)
    if not val or val.strip() in ["Not Applicable", "N/A", "-", "Not Applicable Available"]:
        return None
    return val.strip()


def fetch_description(page, sid):
    # Fetches the threat research description for a given SID from threatintel.proofpoint.com by targeting the Description tab.
    try:
        try:
            desc_tab = page.locator("button, [role='tab']", has_text="Description").first
            if desc_tab.is_visible():
                desc_tab.click(timeout=5000)
                # Wait explicitly for either description text or the explicit empty indicator
                page.locator("text=Description augmented by Proofpoint Nexus, text=Threat Research Generated, text=No Description Available").first.wait_for(timeout=4000)
        except Exception:
            pass

        html = page.content()
        soup = BeautifulSoup(html, "html.parser")
        
        if "No Description Available" in soup.get_text():
            return None

        main_content = soup.find("main", class_=lambda c: c and "MuiBox-root" in c)
        if main_content:
            heading = main_content.find(
                ["h3", "h5", "div"],
                string=lambda s: s and ("Threat Research Generated" in s or "Description augmented by Proofpoint Nexus" in s)
            )
            if heading:
                next_p = heading.find_next_sibling("p", class_=lambda c: c and "MuiTypography-body1" in c)
                if not next_p:
                    parent_div = heading.find_parent("div")
                    if parent_div:
                        next_p = parent_div.find("p", class_=lambda c: c and "MuiTypography-body1" in c)
                
                if next_p and next_p.get_text(strip=True):
                    text_val = next_p.get_text(separator=" ", strip=True)
                    if text_val and text_val != "App Switcher" and len(text_val) > 40:
                        return text_val

        for desc_element in soup.find_all("p", class_=lambda c: c and "MuiTypography-body1" in c):
            text = desc_element.get_text(separator=" ", strip=True)
            if text and text != "App Switcher" and "This feature requires" not in text and len(text) > 40:
                return text

        return None

    except Exception as e:
        print(f"    [!] Browser could not find description for SID {sid}: {e}")
        return None


def fetch_summary_metadata(page, sid):
    # Extracts all metadata fields using precise container/grid matching with active validation waits.
    summary_data = {}
    try:
        try:
            summary_tab = page.locator("button, [role='tab']", has_text="Summary").first
            if summary_tab.is_visible():
                summary_tab.click(timeout=5000)
                # WAIT explicitly for layout container elements to load to eliminate null race conditions
                page.locator("text=Creation Date").first.wait_for(timeout=4000)
        except Exception:
            pass

        html = page.content()
        soup = BeautifulSoup(html, "html.parser")
        
        main_content = soup.find("main", class_=lambda c: c and "MuiBox-root" in c)
        
        known_fields = [
            "Name", "Creation Date", "Last Modified", "Severity", 
            "Affected Products", "Signature Placement", "Attack Target", 
            "Category", "Malware Family", "Performance Impact", "Ruleset"
        ]

        for field in known_fields:
            label_el = soup.find(string=lambda s: s and s.strip() == field)
            if label_el:
                parent = label_el.find_parent(["div", "span", "p", "td"])
                if parent:
                    next_sibling = parent.find_next_sibling()
                    if next_sibling:
                        val = next_sibling.get_text(strip=True)
                        field_key = field.lower().replace(" ", "_")
                        summary_data[field_key] = clean_value(val)
                        continue

                if main_content:
                    text_list = [e.strip() for e in main_content.find_all(string=True) if e.strip()]
                    if field in text_list:
                        idx = text_list.index(field)
                        if idx + 1 < len(text_list):
                            field_val = text_list[idx + 1]
                            if field_val not in known_fields:
                                field_key = field.lower().replace(" ", "_")
                                summary_data[field_key] = clean_value(field_val)

        return summary_data
    except Exception as e:
        print(f"    [!] Error parsing summary metadata for SID {sid}: {e}")
        return {}


def fetch_rule_text_metadata(page, sid):
    # Extracts rule parameters reliably from the RuleText tab using verified structural locators.
    rule_text_data = {
        "references": [],
        "rule_metadata": {}
    }
    try:
        try:
            ruletext_tab = page.locator("button, [role='tab']", has_text="RuleText").first
            if ruletext_tab.is_visible():
                ruletext_tab.click(timeout=5000)
                page.locator("text=Network Match").first.wait_for(timeout=4000)
        except Exception:
            pass

        html = page.content()
        soup = BeautifulSoup(html, "html.parser")
        
        fields_to_extract = {
            "Action": "action",
            "Network Match": "network_match",
            "Flow": "flow",
            "Flowbits": "flowbits",
            "Classtype": "classtype",
            "SID": "sid",
            "REV": "rev"
        }

        for label_text, key in fields_to_extract.items():
            label_el = soup.find(string=lambda s: s and s.strip() == label_text)
            if label_el:
                parent = label_el.find_parent(["div", "span", "p"])
                if parent:
                    sibling = parent.find_next_sibling()
                    if sibling:
                        val = sibling.get_text(strip=True)
                        rule_text_data[key] = clean_value(val)
                        continue
                
                grandparent = label_el.find_parent(["div", "tr", "section"])
                if grandparent:
                    text_nodes = [t.strip() for t in grandparent.stripped_strings]
                    if label_text in text_nodes:
                        idx = text_nodes.index(label_text)
                        if idx + 1 < len(text_nodes):
                            rule_text_data[key] = clean_value(text_nodes[idx + 1])

        # Extract references and rule_metadata from the code/pre block or general text
        code_el = soup.find("code") or soup.find("pre")
        full_rule_text = code_el.get_text(separator=" ", strip=True) if code_el else soup.get_text(separator=" ", strip=True)

        references = []
        for ref_match in re.finditer(r"reference\s*:\s*([^;]+);", full_rule_text, re.IGNORECASE):
            ref_val = clean_value(ref_match.group(1))
            if ref_val:
                references.append(ref_val)
        if references:
            rule_text_data["references"] = list(set(references))

        meta_dict = {}
        for meta_match in re.finditer(r"metadata\s*:\s*([^;]+);", full_rule_text, re.IGNORECASE):
            m_content = meta_match.group(1)
            sub_parts = m_content.strip().split(maxsplit=1)
            if len(sub_parts) == 2:
                meta_dict[sub_parts[0]] = clean_value(sub_parts[1])
            elif len(sub_parts) == 1:
                meta_dict[sub_parts[0]] = True
        if meta_dict:
            rule_text_data["rule_metadata"] = meta_dict

        return rule_text_data
    except Exception as e:
        print(f"    [!] Error parsing RuleText metadata for SID {sid}: {e}")
        return rule_text_data


def format_and_split_rule(raw_record):
    # Converts types and ensures keys are properly normalized
    network_match = raw_record.get("network_match")
    
    parsed_header = {
        "protocol": None,
        "src_net": None,
        "src_port": None,
        "direction": None,
        "dst_net": None,
        "dst_port": None
    }

    if network_match:
        header_pattern = re.compile(
            r"^(?P<protocol>[a-zA-Z0-9_-]+)\s+"
            r"(?P<src_net>\S+)\s+"
            r"(?P<src_port>\S+)\s+"
            r"(?P<direction>->|<->|<>)\s+"
            r"(?P<dst_net>\S+)\s+"
            r"(?P<dst_port>\S+)"
        )
        match = header_pattern.match(network_match.strip())
        if match:
            parsed_header.update(match.groupdict())

    # Guarantee SID is mapped correctly using scraped data or falling back securely to map dictionary value
    sid_val = raw_record.get("sid")
    sid = int(sid_val) if sid_val is not None and str(sid_val).isdigit() else None

    rev_val = raw_record.get("rev")
    rev = int(rev_val) if rev_val is not None and str(rev_val).isdigit() else None

    formatted_record = {
        "sid": sid,
        "rev": rev,
        "msg": raw_record.get("msg"),
        "classtype": raw_record.get("classtype"),
        "action": raw_record.get("action"),
        "protocol": parsed_header["protocol"],
        "src_net": parsed_header["src_net"],
        "src_port": parsed_header["src_port"],
        "direction": parsed_header["direction"],
        "dst_net": parsed_header["dst_net"],
        "dst_port": parsed_header["dst_port"],
        "ruleset": raw_record.get("ruleset", "et/open"),
        "vendor": "Proofpoint",
        "flow": raw_record.get("flow"),
        "flowbits": raw_record.get("flowbits"),
        "references": raw_record.get("references", []),
        "rule_metadata": raw_record.get("rule_metadata"),
        "et_name": raw_record.get("name"),
        "creation_date": raw_record.get("creation_date"),
        "last_modified": raw_record.get("last_modified"),
        "severity": raw_record.get("severity"),
        "affected_products": raw_record.get("affected_products"),
        "signature_placement": raw_record.get("signature_placement"),
        "attack_target": raw_record.get("attack_target"),
        "category": raw_record.get("category"),
        "malware_family": raw_record.get("malware_family"),
        "performance_impact": raw_record.get("performance_impact"),
        "description": raw_record.get("description")
    }

    return formatted_record


def main():
    all_rules = load_sids_from_map(MAP_FILE)

    if TEST_LIMIT:
        print(f"[!] TEST MODE ACTIVE: Limiting processing to first {TEST_LIMIT} rules.")
        all_rules = all_rules[:TEST_LIMIT]
    else:
        print(f"[+] FULL RUN MODE ACTIVE: Processing all {len(all_rules)} rules.")

    results = {}
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            results = json.load(f)
        print(f"[+] Resuming from checkpoint: {len(results)} rules already processed.")

    total = len(all_rules)
    processed_count = 0

    print("[+] Launching headless browser...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720}
        )
        page = context.new_page()

        for idx, rule in enumerate(all_rules, start=1):
            sid_str = str(rule["sid"])

            if sid_str in results and "severity" in results[sid_str] and results[sid_str].get("protocol") is not None:
                continue

            print(f"[{idx}/{total}] Fetching SID {sid_str} metadata and description...")
            
            url = f"https://threatintel.proofpoint.com/sid/{sid_str}"
            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
                # Extra explicit safety wait to ensure initial client-side routing application is completely mounted
                page.locator("button, [role='tab']").first.wait_for(timeout=5000)
            except Exception as e:
                print(f"    [!] Failed to load URL for SID {sid_str}: {e}")
                continue

            # 1. Grab Summary Metadata
            summary_meta = fetch_summary_metadata(page, rule["sid"])

            # 2. Grab RuleText Metadata (including network_match string)
            ruletext_meta = fetch_rule_text_metadata(page, rule["sid"])

            # 3. Grab Description Text
            desc = fetch_description(page, rule["sid"])

            # Assembly dictionary using robust extraction paired with a map-file fallback layer for core tracking identifiers
            raw_scraped_data = {
                "sid": rule["sid"],
                "msg": rule["msg"],
                **summary_meta,
                **ruletext_meta,
                "description": desc
            }

            results[sid_str] = format_and_split_rule(raw_scraped_data)
            processed_count += 1

            if processed_count % 25 == 0:
                with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                print(f"    [--> Saved checkpoint ({len(results)} processed)]")

            time.sleep(REQUEST_DELAY)

        browser.close()

    final_output = list(results.values())
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Processing complete! Saved {len(final_output)} records to {OUTPUT_FILE}.")


if __name__ == "__main__":
    main()