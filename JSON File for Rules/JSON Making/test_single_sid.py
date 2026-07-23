from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

def fetch_rule_data(page, sid):
    url = f"https://threatintel.proofpoint.com/sid/{sid}"
    rule_data = {}

    try:
        print(f"[+] Navigating to SID {sid}...")
        page.goto(url, wait_until="networkidle", timeout=20000)

        # --- 1. PARSE SUMMARY TAB DATA ---
        try:
            page.wait_for_selector("main", timeout=5000)
        except Exception:
            pass

        html = page.content()
        soup = BeautifulSoup(html, "html.parser")
        main_content = soup.find("main", class_=lambda c: c and "MuiBox-root" in c)

        if main_content:
            known_fields = [
                "Name", "Creation Date", "Last Modified", "Severity", 
                "Affected Products", "Signature Placement", "Attack Target", 
                "Category", "Malware Family", "Performance Impact", "Ruleset", "Tags"
            ]
            
            # Using string= instead of text= to avoid deprecation warnings
            elements = main_content.find_all(string=True)
            text_list = [e.strip() for e in elements if e.strip()]

            for idx, text in enumerate(text_list):
                if text in known_fields and idx + 1 < len(text_list):
                    field_key = text.lower().replace(" ", "_")
                    field_val = text_list[idx + 1]
                    if field_val not in known_fields:
                        rule_data[field_key] = field_val

        # --- 2. SWITCH TO DESCRIPTION TAB & PARSE ---
        try:
            desc_tab = page.locator("button, [role='tab']", has_text="Description").first
            desc_tab.click(timeout=3000)
            page.locator("text=Description augmented by Proofpoint Nexus, text=Threat Research Generated").first.wait_for(timeout=4000)
            
            html = page.content()
            soup = BeautifulSoup(html, "html.parser")
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
                        rule_data["description"] = next_p.get_text(separator=" ", strip=True)
        except Exception:
            pass

        if "description" not in rule_data:
            rule_data["description"] = "No detailed description provided on portal."

        return rule_data

    except Exception as e:
        print(f"    [!] Browser error for SID {sid}: {e}")
        return None

# --- Test run ---
with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()
    
    # Test on SID 2000026 (the one from your screenshot)
    data = fetch_rule_data(page, 2000026)
    print("\n--- EXTRACTED RESULT ---")
    print(data)
    
    browser.close()