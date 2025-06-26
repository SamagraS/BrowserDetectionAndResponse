🔍 Project Summary: Real-Time Browser History Analysis & Threat Detection
This project is a Python-based tool that monitors Chrome browser history in real time, performs static analysis on visited URLs, flags potentially malicious or suspicious activity, and captures screenshots of dangerous pages for documentation or forensic analysis.

IMPORTANT - Check Master Branch for full project files.

⚙️ Key Features
Live browser history monitoring while Chrome is running.

Extraction of metadata (domain, path, query params) from visited URLs.

Detection of suspicious TLDs (e.g., .tk, .xyz, .top) and obfuscated elements (e.g., base64, percent-encoding).

Screenshot capture of flagged URLs using a headless browser.

Organized storage of metadata and screenshots for later review.

🧱 Tech Stack
🔸 Core Language:
Python 3.x

🔸 Standard Libraries:
os — file system navigation

shutil — safe file copying

sqlite3 — reading Chrome’s local history database

datetime — time conversion from Chrome timestamps

time — delay between monitoring cycles

urllib.parse — parsing and analyzing URLs

🔸 Browser Automation:
Selenium — automated browsing and screenshot capture

ChromeDriver — required for headless Chrome control

Headless Chrome — for screenshotting URLs without opening a visible browser window

🧠 How It Works
History Polling: Every few seconds, the tool copies Chrome’s History SQLite database to avoid file locks.

Data Extraction: It queries the latest visited URLs and checks if they've already been processed.

Static Analysis: Each new URL is parsed; its domain, path, and parameters are scanned for suspicious traits.

Threat Response: If any red flags are detected, a headless browser opens the page and takes a screenshot, which is stored locally.

Looping: The tool runs continuously, updating and capturing as the user browses.

📁 Output
Text log of all URLs and flagged activity

screenshots/ folder containing images of malicious-looking pages

Easily extendable for integration with VirusTotal, AbuseIPDB, or custom threat feeds
