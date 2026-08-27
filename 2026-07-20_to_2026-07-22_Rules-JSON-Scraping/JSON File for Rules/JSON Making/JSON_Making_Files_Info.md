# JSON File for Rules / JSON Making

Scripts used to build two rule-metadata datasets: a full ET Open ruleset dataset scraped from Proofpoint's threat intel portal, and a smaller sample dataset pulled from OISF's public community rule sources. Includes the tools used to verify, query, and recover that data.

## Files, in the order you'd actually use them

| File | Purpose |
|---|---|
| `et_scraping.py` | **Main scraper.** Reads every SID from `sid-msg.map`, scrapes each rule's metadata (severity, category, malware family, description, references, etc.) from `threatintel.proofpoint.com`, and writes `et_checkpoint.json` + `suricata_et_rules.json`. Async, 6 concurrent workers, checkpoints every 25 records, resumable if interrupted. |
| `verify_scrape.py` | **Run after scraping finishes.** Cross-checks `sid-msg.map`, `et_checkpoint.json`, `failed_sids.json`, and `suricata_et_rules.json` against each other — confirms every SID is accounted for and that the output file matches the checkpoint exactly (including a content spot-check on a 500-record sample). |
| `repair_checkpoint.py` | **Only needed if a checkpoint file gets corrupted** (e.g. cut off mid-write). Recovers valid `"sid": {...}` records out of a broken `et_checkpoint.json` via regex and merges them into a clean backup. Not part of the normal run — a one-off recovery tool. |
| `lookup_rules.py` | **End-user query tool.** Loads `suricata_et_rules.json` into memory and gives you an interactive prompt to search by `sid`, `msg` keyword, or `category`. |
| `generate_rules_json.py` | **Separate dataset, separate source.** Pulls a sample of rules from OISF's free/public rule sources (Abuse.ch, Stamus, IPFire, etc., listed in `index.yaml`) and parses them directly from the `.rules` files into `suricata_community_sample.json`. Not related to the ET/Proofpoint scrape — this is a smaller, independently-sourced dataset. |
| `test_single_sid.py` | **Dev/debug scratch script**, not part of the pipeline. Early synchronous-Playwright prototype used to work out the scraping logic on a single hardcoded SID before `et_scraping.py` was built. Kept for reference; safe to leave out if you want a leaner folder. |

## Datasets

Two separate final datasets come out of this folder — both are JSON **lists** of rule-record objects (an array of dicts), ready to load with `json.load()` and iterate directly:

| Dataset | Source | Built by | Format | Record shape |
|---|---|---|---|---|
| `suricata_et_rules.json` | Emerging Threats rules, scraped from `threatintel.proofpoint.com` per SID | `et_scraping.py` | List | `[{...}, {...}, ...]` — `sid`, `rev`, `msg`, `classtype`, `action`, `protocol`, `src_net`, `src_port`, `direction`, `dst_net`, `dst_port`, `ruleset`, `vendor`, `flow`, `flowbits`, `references`, `rule_metadata`, `et_name`, `creation_date`, `last_modified`, `severity`, `affected_products`, `signature_placement`, `attack_target`, `category`, `malware_family`, `performance_impact`, `description` |
| `suricata_community_sample.json` | OISF's free/public community rule sources (Abuse.ch, Stamus, IPFire, etc.) | `generate_rules_json.py` | List | `[{...}, {...}, ...]` — `sid`, `rev`, `msg`, `classtype`, `action`, `protocol`, `src_net`, `src_port`, `direction`, `dst_net`, `dst_port`, `ruleset`, `vendor`, `flow`, `flowbits`, `references`, `rule_metadata`, `source_description`, `raw_rule` |

They're independent datasets from different sources — not two versions of the same thing. `suricata_et_rules.json` is the big one (full ET Open ruleset); `suricata_community_sample.json` is a smaller sample across several free vendor feeds.

Note the difference in shape from the *intermediate* files below: `et_checkpoint.json` is a **dict** keyed by SID (`{"2000026": {...}, ...}`), used internally so the scraper can resume. `suricata_et_rules.json` is that same data flattened into a plain **list** (`[{...}, {...}]`) — the list form is the one meant for actual use/sharing, the dict form is just scrape-resume bookkeeping.

## Working/intermediate files

- `sid-msg.map` — **not JSON**, plain text, one rule per line, `sid||msg||...` pipe-delimited. Source list of all SIDs + short messages, the input to `et_scraping.py`
- `et_checkpoint.json` / `et_checkpoint_backup.json` — **dict**, `{"2000026": {...}, "2000027": {...}, ...}`, SID string → full record. Resumable scrape state
- `failed_sids.json` — **list**, `["2000030", "2000045", ...]` — SIDs that failed to scrape after retries
- `scraping_log.txt` — **not JSON**, plain text log, full run log from `et_scraping.py`

## Opening these files

`et_checkpoint.json` and `suricata_et_rules.json` cover all ~71k SIDs and are large enough (tens to 100+ MB) that VS Code's editor will hang, lag badly, or refuse to open them at all. Don't try to open them as a normal text file. Instead:

- **To just look around / spot-check a few records:** use [Big JSON Viewer](https://www.bigjsonviewer.com/), tested up to 500MB, runs entirely in the browser (nothing uploaded), search with Ctrl+F, double-click any item to see its full value. VS Code extensions like "Big JSON" work similarly by lazily rendering the tree instead of parsing the full file at once.
- **To actually query or check things:** use `lookup_rules.py` (already built for this — search by `sid`, `msg`, or `category` without opening the file at all), or load it in a Python/`jq` one-liner instead of an editor:
  ```bash
  jq '.[0]' suricata_et_rules.json          # first record
  jq 'length' suricata_et_rules.json        # record count
  jq '.[] | select(.sid == 2000026)' suricata_et_rules.json
  ```
- `suricata_community_sample.json` and `failed_sids.json` are much smaller and open fine in VS Code as-is.

## Setup

```bash
pip install playwright beautifulsoup4 requests pyyaml
playwright install chromium
```

## Known limitations, worth knowing before reusing this

- `et_scraping.py` scrapes a live third-party site by parsing its rendered HTML/CSS classes. If Proofpoint changes their page layout, the field extraction will silently return fewer fields (not crash) — re-run `verify_scrape.py` after any re-scrape to catch that.
- `generate_rules_json.py`'s rule parser expects each rule on a single line matching a fixed regex. Multi-line or unusually formatted rules are skipped without being counted or logged, so the output count is a lower bound, not a guaranteed-complete parse.
- `repair_checkpoint.py` extracts JSON objects with a regex rather than a real parser. It works for the corruption pattern it was written for (truncated file with leading null bytes) but isn't a general-purpose JSON repair tool.
