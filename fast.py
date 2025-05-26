# Dependencies: streamlit, pandas, requests, openpyxl
import streamlit as st
import pandas as pd
import requests
import time
import base64
import re
import ipaddress
from io import BytesIO
from urllib.parse import urlparse

# Configure Streamlit page
st.set_page_config(page_title="VirusTotal IOC Scanner", layout="wide")
st.title("VirusTotal IOC Scanner")

# Input field for VirusTotal API key (type=password to hide input)
api_key = st.text_input("You api key", type="password")

# Multiline text box for IOCs (one per line)
ioc_input = st.text_area("Enter IOCs (one per line)", height=200, 
                         help="Paste URLs, IPs, domains, or hashes, each on a new line.")

# Button to start scanning
if st.button("Scan IOCs"):
    # Validate inputs
    if not api_key:
        st.error("Please enter a VirusTotal API key.")
    elif not ioc_input:
        st.error("Please enter at least one IOC to scan.")
    else:
        # Split input into lines and remove empty ones
        ioc_list = [line.strip() for line in ioc_input.splitlines() if line.strip()]
        if not ioc_list:
            st.error("No valid IOCs found. Please enter URLs, IPs, domains, or hashes.")
        else:
            # Prepare DataFrame results list
            results = []
            # Set up progress bar and status message
            progress_bar = st.progress(0)
            status_text = st.empty()

            headers = {"x-apikey": api_key}
            base_url = "https://www.virustotal.com/api/v3"

            # Iterate through IOCs
            for idx, ioc in enumerate(ioc_list):
                status_text.text(f"Processing {ioc} ({idx+1}/{len(ioc_list)})...")
                ioc_type = None
                vt_url = None

                # Determine IOC type: URL, IP, domain, or file hash
                parsed = urlparse(ioc)
                # Check if it's a full URL (has scheme)
                if parsed.scheme in ("http", "https"):
                    ioc_type = "url"
                    url_to_query = ioc
                else:
                    # Check if it's a URL missing scheme (contains a slash after domain)
                    if parsed.scheme == "" and parsed.netloc == "" and "/" in parsed.path:
                        parsed2 = urlparse("http://" + ioc)
                        if parsed2.netloc:
                            ioc_type = "url"
                            url_to_query = "http://" + ioc

                # Check if it's an IP address
                if not ioc_type:
                    try:
                        ipaddress.ip_address(ioc)
                        ioc_type = "ip"
                    except ValueError:
                        pass

                # Check if it's a file hash (MD5, SHA1, SHA256)
                if not ioc_type:
                    # Only hex strings of length 32, 40, or 64
                    hash_pattern = re.compile(r'^[A-Fa-f0-9]{32,64}$')
                    if hash_pattern.match(ioc) and len(ioc) in (32, 40, 64):
                        ioc_type = "file"

                # If still not identified, assume it's a domain
                if not ioc_type:
                    ioc_type = "domain"

                # Construct VirusTotal API URL based on IOC type
                try:
                    if ioc_type == "url":
                        # For URLs, use base64 URL-safe encoding of the full URL
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

                    # Make the API request
                    response = requests.get(vt_url, headers=headers)
                except Exception as e:
                    st.error(f"Error preparing request for IOC {ioc}: {e}")
                    continue

                # Handle rate limiting (HTTP 429) by waiting and retrying once
                if response.status_code == 429:
                    st.warning("Rate limit reached (4 requests/min). Waiting 60 seconds...")
                    time.sleep(60)
                    try:
                        response = requests.get(vt_url, headers=headers)
                    except Exception as e:
                        st.error(f"Request failed for {ioc} after waiting: {e}")
                        continue

                # Check for successful response
                if response.status_code != 200:
                    st.error(f"Failed to retrieve data for IOC {ioc}. HTTP status: {response.status_code}")
                    continue

                # Parse JSON response and extract analysis stats
                try:
                    data = response.json().get("data", {})
                    attributes = data.get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                except Exception as e:
                    st.error(f"Error parsing response for {ioc}: {e}")
                    continue

                # Add to results
                results.append({
                    "IOC": ioc,
                    "Type": ioc_type,
                    "Malicious": malicious,
                    "Suspicious": suspicious,
                    "Harmless": harmless,
                    "Undetected": undetected
                })

                # Update progress bar
                progress = int((idx + 1) / len(ioc_list) * 100)
                progress_bar.progress(progress)

                # Sleep ~15 seconds between requests to handle rate limit (4/minute)
                if idx < len(ioc_list) - 1:
                    time.sleep(15)

            # After scanning all IOCs
            status_text.text("Scan complete.")

            # Display results if any
            if results:
                df = pd.DataFrame(results)
                st.dataframe(df)

                # Provide download button for Excel file
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
