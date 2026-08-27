# Suricata IDS Lab

Internship project on Suricata: learning the tool, building a rule dataset, building a custom monitoring dashboard, and testing detection against simulated attacks in a 3-machine virtual lab (Kali attacker, Ubuntu-Benign, Ubuntu-Suricata).

Dashboard code lives in a separate repo: **[suricata-dashboard](https://github.com/Sameeha135/suricata-dashboard)**.

## Lab setup

- Kali (attacker), Ubuntu-Benign, Ubuntu-Suricata — 3 VMs on a shared subnet
- Suricata running in `af-packet` mode on the Ubuntu-Suricata VM, monitoring traffic between Kali and Ubuntu-Benign
- Traffic simulated two ways: live tools from Kali (nmap, Nikto) and replayed PCAPs (`tcprewrite` + `tcpreplay`) sourced from malware-traffic-analysis.net

## Day-wise breakdown

| Dates | Folder | What it covers |
|---|---|---|
| Jul 14 | `2026-07-14_VMware-Setup` | 3-VM lab setup |
| Jul 15 | `2026-07-15_Suricata-Rules-Explore` | Suricata fundamentals, rule anatomy |
| Jul 16 | `2026-07-16_Dashboard-OpenSource-Research` | Evaluated [suricata-lightweight-gui](https://github.com/daxAKAhackerman/suricata-lightweight-gui) as a reference |
| Jul 17 | `2026-07-17_Suricata-Rules-Research` | Rule sources, SID allocation system |
| Jul 20–22 | `2026-07-20_to_2026-07-22_Rules-JSON-Making` | Scraped ET rule metadata into a structured JSON dataset (checkpointed scraper, ~34.7k rules) |
| Jul 23–24 | `2026-07-23_to_2026-07-24_Setup-for-Streamlit` | Environment + repo setup for the custom dashboard |
| Jul 27–Aug 3 | `2026-07-27_to_2026-07-31_Suricata-Dashboard` | Core dashboard build, then scraping work alongside it (Jul 29), then further dashboard/DB changes running to Aug 3 |
| Aug 5–6 | `2026-08-03_to_2026-08-06_Dashboard-...` | Dashboard speed optimization (Aug 5) and write-up (Aug 6) |
| Aug 7–10 | `2026-08-07_to_2026-08-10_PCAP-Starting` | PCAP capture/replay method: `tcpdump`, `tshark`, `tcprewrite`, `tcpreplay` |
| Aug 11–12 | `2026-08-11_to_2026-08-12_PCAP-Nikto` | Nikto web-scan replay (Aug 11); ET scraping wrapped up here too (Aug 12) — worth double-checking this folder has both sets of notes, not just the PCAP ones |
| Aug 13–17 | `2026-08-13_to_2026-08-17_PCAP-Multi` | Three distinct attack flows replayed, sourced from [malware-traffic-analysis.net](https://malware-traffic-analysis.net/training-exercises.html) |
| Aug 19–20 | `2026-08-19_to_2026-08-20_PCAP-5-Attackers` | Multi-attacker simulation (5 source IPs) |
| Aug 24–28 | `2026-08-24_to_2026-08-28_Documentation` | Final presentation, repo cleanup/organization |

Each folder contains that period's notes, scripts, and (where relevant) PCAPs or screenshots.

## Rule dataset

- `sid-msg.map`, `generate_rules_json.py`, `et_scraping.py` — build a JSON dataset of ET rule metadata by SID
- Checkpointed and resumable (`et_checkpoint.json`, `failed_sids.json`)
- Output verified for consistency against the source data (`verify_scrape.py`)

## Dashboard (own build)

- Built with Streamlit, SQLite backend (WAL mode)
- Modular: `ingestor.py`, `alert_store.py`, `data_loader.py`, `filters.py`, `charts.py`, `app.py`
- Filters and displays live traffic + alerts, with metadata drill-down per alert

## Attack simulation

- PCAPs sourced from malware-traffic-analysis.net, IPs remapped with `tcprewrite` to fit the lab subnet, replayed with `tcpreplay`
- Covered: Nikto web scan, a 5-attacker simulation, and three distinct attack flows:
  1. **Formbook / XLoader** — C2 traffic
  2. **Web recon/exploitation probes**
  3. **GuLoader → AgentTesla** — with FTP data exfiltration
- Suricata alerts cross-checked against expected signatures for each replay

## Links

- Dashboard repo: https://github.com/Sameeha135/suricata-dashboard
- Presentation: `2026-08-24_to_2026-08-28_Documentation/Suricata_Project_Presentation.pptx`
- Google Drive (datasets, PCAPs, exports): (add link)