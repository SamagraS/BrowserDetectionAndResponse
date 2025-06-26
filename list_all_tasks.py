import sqlite3
import os
import time
import datetime
import shutil
import vt
import json
import sys
from urllib.parse import urlparse

if sys.platform == "win32":
    os.system("chcp 65001 > nul")  # Set console to UTF-8
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

API_Key = "0bc177f77cd35a5cbdff334b16409b232e79b1fe1bbc0638e5778a82403912df"
client = vt.Client(API_Key)

# Chrome history path
HISTORY_PATH = os.environ['USERPROFILE'] + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
COPY_PATH = "History_copy"

# Store the URLs seen and their scan results
seen_urls = set()
url_scan_cache = {}

# Convert Chrome stamp to actual date and time
def chrome_time_to_datetime(chrome_time):
    epoch_start = datetime.datetime(1601, 1, 1)
    return epoch_start + datetime.timedelta(microseconds=chrome_time)

def get_domain_from_url(url):
    """Extract domain from URL for better display"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return url

def scan_url_with_virustotal(url):
    """Scan URL with VirusTotal and return security info"""
    try:
        # Check if we already scanned this URL
        if url in url_scan_cache:
            return url_scan_cache[url]

        print(f"[SCAN] Scanning URL: {get_domain_from_url(url)}")

        # Get URL ID and scan
        url_id = vt.url_id(url)

        try:
            url_obj = client.get_object("/urls/{}", url_id)
        except vt.APIError as e:
            if e.code == "NotFoundError":
                # URL not found in VT database, submit for analysis
                try:
                    client.scan_url(url)
                    print("    [INFO] Submitted for scan, waiting for results...")

                    for attempt in range(20):
                        time.sleep(1)
                        try:
                            url_obj = client.get_object("/urls/{}", url_id)
                            stats = url_obj.get("last_analysis_stats", {})
                            if stats and sum(stats.values()) > 0:
                                break
                        except:
                            continue
                    else:
                        print("    [WARN] Timed out waiting for scan results.")
                        return {
                            'status': "[SCAN] SUBMITTED BUT NO RESULT YET",
                            'malicious': 0,
                            'suspicious': 0,
                            'total_engines': 0,
                            'scan_date': 'Pending',
                            'ip_address': 'Unknown',
                            'country': 'Unknown',
                            'asn': 'Unknown'
                        }
                except Exception as submit_error:
                    print(f"[ERROR] Failed to submit URL for scanning: {submit_error}")
                    return None
            else:
                print(f"[ERROR] VirusTotal API error: {e}")
                return None

        # Extract relevant security information
        stats = url_obj.last_analysis_stats
        scan_date = url_obj.last_analysis_date

        # Calculate threat level
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total_engines = sum(stats.values())

        # Determine status (using safe characters for Windows compatibility)
        if malicious > 0:
            status = "[!] MALICIOUS"
        elif suspicious > 0:
            status = "[?] SUSPICIOUS"
        else:
            status = "[OK] CLEAN"

        ip_address = "Unknown"
        country = "Unknown"
        asn = "Unknown"

        domain = get_domain_from_url(url)
        if domain:
            try:
                domain_obj = client.get_object(f"/domains/{domain}")
                ip_address = domain_obj.get("last_dns_records", [{}])[-1].get("value", "Unknown")
                country = domain_obj.get("country", "Unknown")
                asn = domain_obj.get("asn", "Unknown")
            except Exception as e:
                print(f"[DEBUG] Failed to get domain metadata: {e}")

        scan_result = {
            'status': status,
            'malicious': malicious,
            'suspicious': suspicious,
            'total_engines': total_engines,
            'scan_date': scan_date.strftime('%Y-%m-%d %H:%M:%S') if scan_date else 'Unknown',
            'ip_address': ip_address,
            'country': country,
            'asn': asn
        }

        # Cache the result
        url_scan_cache[url] = scan_result
        return scan_result

    except Exception as e:
        print(f"[ERROR] Failed to scan URL: {e}")
        return None

def get_latest_history():
    try:
        # Avoid file lock
        shutil.copy(HISTORY_PATH, COPY_PATH)
        conn = sqlite3.connect(COPY_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT url, title, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 20
        """)
        new_entries = []
        for row in cursor.fetchall():
            url, title, visit_time = row
            if url not in seen_urls:
                seen_urls.add(url)

                # Scan URL with VirusTotal
                scan_result = scan_url_with_virustotal(url)

                new_entries.append((
                    chrome_time_to_datetime(visit_time),
                    title,
                    url,
                    scan_result
                ))

        conn.close()
        os.remove(COPY_PATH)
        return new_entries

    except Exception as e:
        print(f"[!] Error reading history: {e}")
        return []

def print_scan_summary():
    """Print a summary of scanned URLs"""
    if not url_scan_cache:
        return

    malicious_count = sum(1 for result in url_scan_cache.values() if result and result['malicious'] > 0)
    suspicious_count = sum(1 for result in url_scan_cache.values() if result and result['suspicious'] > 0)
    clean_count = sum(1 for result in url_scan_cache.values() if result and result['malicious'] == 0 and result['suspicious'] == 0)

    print(f"\n{'='*60}")
    print(f"SCAN SUMMARY: {len(url_scan_cache)} URLs scanned")
    print(f"[!] Malicious: {malicious_count}")
    print(f"[?] Suspicious: {suspicious_count}")
    print(f"[OK] Clean: {clean_count}")
    print(f"{'='*60}\n")

# Main monitoring loop
print("Chrome History Monitor with VirusTotal Scanner")
print("=" * 50)
print("Monitoring Chrome history... (Press Ctrl+C to stop)")
print("Note: First-time scans may take a few seconds per URL\n")

try:
    while True:
        entries = get_latest_history()

        for visit_time, title, url, scan_result in entries:
            # Basic info
            try:
                print(f"[{visit_time}] {title}")
                print(f"    URL: {url}")

                # Security scan results
                if scan_result:
                    print(f"    Security: {scan_result['status']}")
                    print(f"    Engines: {scan_result['malicious']}/{scan_result['total_engines']} flagged as malicious")
                    print(f"    Scan Date: {scan_result['scan_date']}")
                    print(f"    IP: {scan_result['ip_address']} | ASN: {scan_result['asn']} | Country: {scan_result['country']}")
                else:
                    print(f"    Security: SCAN FAILED")

                print("-" * 80)

            except UnicodeEncodeError:
                # Fallback for encoding issues
                print(f"[{visit_time}] [Title contains special characters]")
                print(f"    URL: {url}")
                if scan_result:
                    print(f"    Security: {scan_result['status']}")
                print("-" * 80)

        if entries:
            print_scan_summary()

        time.sleep(10)  # Increased interval to respect VT API limits

except KeyboardInterrupt:
    print("\n\nStopping monitor...")
    print_scan_summary()

except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")

finally:
    try:
        client.close()
    except:
        pass
