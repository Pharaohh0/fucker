# vt_ioc_scanner.py
import streamlit as st
import pandas as pd
import requests
import time
import base64
import re
import ipaddress
from io import BytesIO
from urllib.parse import urlparse

st.set_page_config(page_title="VirusTotal IOC Scanner", layout="wide")
st.title("VirusTotal IOC Scanner")

api_key = st.text_input("Enter your VirusTotal API key", type="password")
ioc_input = st.text_area("Enter IOCs (one per line)", height=200, 
                         help="Paste URLs, IPs, domains, or hashes, each on a new line.")

if st.button("Scan IOCs"):
    if not api_key:
        st.error("Please enter a VirusTotal API key.")
    elif not ioc_input:
        st.error("Please enter at least one IOC to scan.")
    else:
        ioc_list = [line.strip() for line in ioc_input.splitlines() if line.strip()]
        if not ioc_list:
            st.error("No valid IOCs found. Please enter URLs, IPs, domains, or hashes.")
        else:
            results = []
            progress_bar = st.progress(0)
            status_text = st.empty()

            headers = {"x-apikey": api_key}
            base_url = "https://www.virustotal.com/api/v3"

            for idx, ioc in enumerate(ioc_list):
                status_text.text(f"Processing {ioc} ({idx+1}/{len(ioc_list)})...")
                ioc_type = None
                vt_url = None

                parsed = urlparse(ioc)
                if parsed.scheme in ("http", "https"):
                    ioc_type = "url"
                    url_to_query = ioc
                elif parsed.scheme == "" and parsed.netloc == "" and "/" in parsed.path:
                    parsed2 = urlparse("http://" + ioc)
                    if parsed2.netloc:
                        ioc_type = "url"
                        url_to_query = "http://" + ioc
                if not ioc_type:
                    try:
                        ipaddress.ip_address(ioc)
                        ioc_type = "ip"
                    except ValueError:
                        pass
                if not ioc_type:
                    hash_pattern = re.compile(r'^[A-Fa-f0-9]{32,64}$')
                    if hash_pattern.match(ioc) and len(ioc) in (32, 40, 64):
                        ioc_type = "file"
                if not ioc_type:
                    ioc_type = "domain"

                try:
                    if ioc_type == "url":
                        url_id = base64.urlsafe_b64encode(url_to_query.encode()).decode().strip("=")
                        vt_url = f"{base_url}/urls/{url_id}"
                    elif ioc_type == "ip":
                        vt_url = f"{base_url}/ip_addresses/{ioc}"
                    elif ioc_type == "domain":
                        vt_url = f"{base_url}/domains/{ioc}"
                    elif ioc_type == "file":
                        vt_url = f"{base_url}/files/{ioc}"
                    else:
                        vt_url = None

                    if not vt_url:
                        raise ValueError("Unable to determine API endpoint for IOC.")

                    response = requests.get(vt_url, headers=headers)
                except Exception as e:
                    results.append({
                        "IOC": ioc,
                        "Type": ioc_type,
                        "Malicious": "Error",
                        "Suspicious": "Error",
                        "Harmless": "Error",
                        "Undetected": "Error"
                    })
                    continue

                if response.status_code in [400, 404]:
                    results.append({
                        "IOC": ioc,
                        "Type": ioc_type,
                        "Malicious": "Not Found",
                        "Suspicious": "Not Found",
                        "Harmless": "Not Found",
                        "Undetected": "Not Found"
                    })
                    continue
                elif response.status_code != 200:
                    results.append({
                        "IOC": ioc,
                        "Type": ioc_type,
                        "Malicious": f"HTTP {response.status_code}",
                        "Suspicious": f"HTTP {response.status_code}",
                        "Harmless": f"HTTP {response.status_code}",
                        "Undetected": f"HTTP {response.status_code}"
                    })
                    continue

                try:
                    data = response.json().get("data", {})
                    attributes = data.get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                except Exception as e:
                    malicious = suspicious = harmless = undetected = "Parse Error"

                results.append({
                    "IOC": ioc,
                    "Type": ioc_type,
                    "Malicious": malicious,
                    "Suspicious": suspicious,
                    "Harmless": harmless,
                    "Undetected": undetected
                })

                progress = int((idx + 1) / len(ioc_list) * 100)
                progress_bar.progress(progress)

                if idx < len(ioc_list) - 1:
                    time.sleep(15)

            status_text.text("Scan complete.")
            if results:
                df = pd.DataFrame(results)
                st.dataframe(df)

                output = BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    df.to_excel(writer, index=False, sheet_name="VT_Report")
                processed_data = output.getvalue()

                st.download_button(label="Download Results as Excel",
                                   data=processed_data,
                                   file_name="vt_ioc_report.xlsx",
                                   mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            else:
                st.warning("No data to display. Check inputs and try again.")