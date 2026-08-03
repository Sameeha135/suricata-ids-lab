import os
import asyncio
import json
import re
import logging
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

# --- Configuration ---
MAP_FILE = "sid-msg.map"
OUTPUT_FILE = "suricata_et_rules.json"
CHECKPOINT_FILE = "et_checkpoint.json"
LOG_FILE = "scraping_log.txt"
FAILED_SIDS_FILE = "failed_sids.json"

# This machine handles SIDs from START_INDEX up to (not including) END_INDEX,
# based on position in sid-msg.map - NOT based on SID number itself. This is
# what keeps local and Kaggle from ever double-processing the same range.
START_INDEX = 0
END_INDEX = 35000  # local stops here; Kaggle picks up from 35000 onward

TEST_LIMIT = None  # set to a small number to smoke-test, None for full range
REQUEST_DELAY = 0.3  # per-worker delay - lower now that we run several workers in parallel
CONCURRENCY = 6  # number of pages scraping simultaneously - start here, raise cautiously

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    encoding="utf-8"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)


def load_sids_from_map(file_path):
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
    if not val or val.strip() in ["Not Applicable", "N/A", "-", "Not Applicable Available"]:
        return None
    return val.strip()


async def fetch_description(page, sid):
    try:
        try:
            desc_tab = page.locator("button, [role='tab']", has_text="Description").first
            if await desc_tab.is_visible():
                await desc_tab.click(timeout=4000)
                await page.locator(
                    "text=Description augmented by Proofpoint Nexus, text=Threat Research Generated, text=No Description Available"
                ).first.wait_for(timeout=3000)
        except Exception:
            pass

        html = await page.content()
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
        logging.warning(f"    [!] Could not find description for SID {sid}: {e}")
        return None


async def fetch_summary_metadata(page, sid):
    summary_data = {}
    try:
        try:
            summary_tab = page.locator("button, [role='tab']", has_text="Summary").first
            if await summary_tab.is_visible():
                await summary_tab.click(timeout=4000)
                await page.locator("text=Creation Date").first.wait_for(timeout=3000)
        except Exception:
            pass

        html = await page.content()
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
        logging.warning(f"    [!] Error parsing summary metadata for SID {sid}: {e}")
        return {}


async def fetch_rule_text_metadata(page, sid):
    rule_text_data = {"references": [], "rule_metadata": {}}
    try:
        try:
            ruletext_tab = page.locator("button, [role='tab']", has_text="RuleText").first
            if await ruletext_tab.is_visible():
                await ruletext_tab.click(timeout=4000)
                await page.locator("text=Network Match").first.wait_for(timeout=3000)
        except Exception:
            pass

        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")

        fields_to_extract = {
            "Action": "action", "Network Match": "network_match", "Flow": "flow",
            "Flowbits": "flowbits", "Classtype": "classtype", "SID": "sid", "REV": "rev"
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
        logging.warning(f"    [!] Error parsing RuleText metadata for SID {sid}: {e}")
        return rule_text_data


def format_and_split_rule(raw_record):
    network_match = raw_record.get("network_match")
    parsed_header = {"protocol": None, "src_net": None, "src_port": None,
                      "direction": None, "dst_net": None, "dst_port": None}
    if network_match:
        header_pattern = re.compile(
            r"^(?P<protocol>[a-zA-Z0-9_-]+)\s+(?P<src_net>\S+)\s+(?P<src_port>\S+)\s+"
            r"(?P<direction>->|<->|<>)\s+(?P<dst_net>\S+)\s+(?P<dst_port>\S+)"
        )
        match = header_pattern.match(network_match.strip())
        if match:
            parsed_header.update(match.groupdict())

    sid_val = raw_record.get("sid")
    sid = int(sid_val) if sid_val is not None and str(sid_val).isdigit() else None
    rev_val = raw_record.get("rev")
    rev = int(rev_val) if rev_val is not None and str(rev_val).isdigit() else None

    return {
        "sid": sid, "rev": rev, "msg": raw_record.get("msg"),
        "classtype": raw_record.get("classtype"), "action": raw_record.get("action"),
        "protocol": parsed_header["protocol"], "src_net": parsed_header["src_net"],
        "src_port": parsed_header["src_port"], "direction": parsed_header["direction"],
        "dst_net": parsed_header["dst_net"], "dst_port": parsed_header["dst_port"],
        "ruleset": raw_record.get("ruleset", "et/open"), "vendor": "Proofpoint",
        "flow": raw_record.get("flow"), "flowbits": raw_record.get("flowbits"),
        "references": raw_record.get("references", []), "rule_metadata": raw_record.get("rule_metadata"),
        "et_name": raw_record.get("name"), "creation_date": raw_record.get("creation_date"),
        "last_modified": raw_record.get("last_modified"), "severity": raw_record.get("severity"),
        "affected_products": raw_record.get("affected_products"),
        "signature_placement": raw_record.get("signature_placement"),
        "attack_target": raw_record.get("attack_target"), "category": raw_record.get("category"),
        "malware_family": raw_record.get("malware_family"), "performance_impact": raw_record.get("performance_impact"),
        "description": raw_record.get("description")
    }


async def scrape_one(context, rule, results, failed_sids, lock, save_progress):
    """One worker's job for one SID - opens its own page, scrapes, closes it."""
    sid_str = str(rule["sid"])
    if sid_str in results and "severity" in results[sid_str] and results[sid_str].get("protocol") is not None:
        return

    page = await context.new_page()
    try:
        url = f"https://threatintel.proofpoint.com/sid/{sid_str}"
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            await page.locator("button, [role='tab']").first.wait_for(timeout=4000)
        except Exception as e:
            logging.warning(f"Failed to load URL for SID {sid_str}: {e}")
            async with lock:
                if sid_str not in failed_sids:
                    failed_sids.append(sid_str)
            return

        summary_meta = await fetch_summary_metadata(page, rule["sid"])
        ruletext_meta = await fetch_rule_text_metadata(page, rule["sid"])
        desc = await fetch_description(page, rule["sid"])

        raw_scraped_data = {"sid": rule["sid"], "msg": rule["msg"], **summary_meta, **ruletext_meta, "description": desc}

        async with lock:
            results[sid_str] = format_and_split_rule(raw_scraped_data)
            if len(results) % 25 == 0:
                save_progress()
                logging.info(f"Checkpoint saved - {len(results)} processed, {len(failed_sids)} failed so far")

    except Exception as e:
        logging.error(f"Unexpected error processing SID {sid_str}: {e}")
        async with lock:
            if sid_str not in failed_sids:
                failed_sids.append(sid_str)
    finally:
        await page.close()
        await asyncio.sleep(REQUEST_DELAY)


async def worker(name, queue, context, results, failed_sids, lock, save_progress):
    while True:
        rule = await queue.get()
        if rule is None:
            queue.task_done()
            break
        await scrape_one(context, rule, results, failed_sids, lock, save_progress)
        queue.task_done()


async def main():
    all_rules = load_sids_from_map(MAP_FILE)
    all_rules = all_rules[START_INDEX:END_INDEX]
    logging.info(f"Processing index range [{START_INDEX}:{END_INDEX}] - {len(all_rules)} rules")

    if TEST_LIMIT:
        all_rules = all_rules[:TEST_LIMIT]
        logging.info(f"TEST MODE ACTIVE: limiting to first {TEST_LIMIT} rules in this range.")

    results = {}
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            results = json.load(f)
        logging.info(f"Resuming from checkpoint: {len(results)} rules already processed.")

    failed_sids = []
    if os.path.exists(FAILED_SIDS_FILE):
        with open(FAILED_SIDS_FILE, "r", encoding="utf-8") as f:
            failed_sids = json.load(f)

    lock = asyncio.Lock()

    def save_progress():
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(list(results.values()), f, indent=2, ensure_ascii=False)
        with open(FAILED_SIDS_FILE, "w", encoding="utf-8") as f:
            json.dump(failed_sids, f, indent=2, ensure_ascii=False)

    browser = None
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720}
            )

            queue = asyncio.Queue()
            for rule in all_rules:
                queue.put_nowait(rule)
            for _ in range(CONCURRENCY):
                queue.put_nowait(None)  # sentinel to stop each worker

            workers = [
                asyncio.create_task(worker(f"w{i}", queue, context, results, failed_sids, lock, save_progress))
                for i in range(CONCURRENCY)
            ]
            await queue.join()
            for w in workers:
                w.cancel()

            await browser.close()
            browser = None

    except KeyboardInterrupt:
        logging.warning("Scraping interrupted by user (Ctrl+C). Saving progress before exit...")
    except Exception as e:
        logging.critical(f"Scraping stopped due to an unexpected error: {e}", exc_info=True)
    finally:
        if browser:
            try:
                await browser.close()
            except Exception:
                pass
        save_progress()
        logging.info(f"Final save complete. {len(results)} total records, {len(failed_sids)} failed SIDs logged.")


if __name__ == "__main__":
    asyncio.run(main())