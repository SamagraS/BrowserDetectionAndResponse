import list_all_tasks
import vt
import time

API_Key = "0bc177f77cd35a5cbdff334b16409b232e79b1fe1bbc0638e5778a82403912df"
client = vt.Client(API_Key)

url_check = list_all_tasks.new_entries

for x in url_check:
    print(f"Submitting {x} to VirusTotal...")
    analysis = client.scan_url(x)

    # Wait for the scan to complete
    for i in range(10):
        analysis_result = client.get_object(f"/analyses/{analysis.id}")
        if analysis_result.status == "completed":
            break
        print(f"Waiting for analysis... (status: {analysis_result.status})")
        time.sleep(5)

    url_id = vt.url_id(x)
    url_report = client.get_object(f"/urls/{url_id}")

    print(f"\n--- Results for {x} ---")
    print("Malicious detections:", url_report.last_analysis_stats['malicious'])
    print("Suspicious detections:", url_report.last_analysis_stats['suspicious'])
    print("Harmless detections: ", url_report.last_analysis_stats['harmless'])
    print("-----------------------------\n")

client.close()
