CNAMERecon Pro 🛡️

Advanced Subdomain CNAME Scanner & Takeover Verifier

CNAMERecon Pro is a professional tool for bug bounty hunters, security researchers, and pentesters. It scans a domain and its subdomains for CNAME records, detects services, verifies potential subdomain takeovers using error response signatures, and provides colorful, detailed outputs.

🧠 Features

✅ Scan a single domain or multiple subdomains from a file

✅ Resolve CNAME records and detect hosting services (AWS, Netlify, GitHub Pages, Azure, Heroku, Fastly, Google Cloud)

✅ HTTP request verification with status codes

✅ Detect potential subdomain takeovers with real error response fingerprints

✅ Filter results based on HTTP status code (--status 404)

✅ Export results to JSON and CSV

✅ Colorful terminal output with severity and takeover status

✅ Clean Ctrl+C exit with thread-safe shutdown

💻 Installation

Clone the repository:

git clone https://github.com/yourusername/cnamerecon-pro.git
cd cnamerecon-pro


Install dependencies:

pip3 install -r requirements.txt


Requirements:

Python 3.10+

requests

colorama

📜 Usage
Scan a single domain:
python3 cnamercon_pro.py -d example.com

Scan multiple subdomains from a file:
python3 cnamercon_pro.py -f subdomains.txt

Filter results by HTTP status code:
python3 cnamercon_pro.py -f subdomains.txt --status 404

Save results to JSON & CSV:
python3 cnamercon_pro.py -f subdomains.txt -o output/results

Multi-threading:
python3 cnamercon_pro.py -f subdomains.txt -t 20

🖌️ Output Example
[+] test.example.com                     → test.netlifyglobalcdn.com          | Netlify      | HTTP 404 | LIKELY TAKEOVER CONFIRMED
[+] app.example.com                      → app.github.io                      | GitHub Pages | HTTP 200 | POSSIBLE
[-] old.example.com                      → No CNAME


Red = Likely takeover

Green = Safe or possible

HTTP status code is shown in color: 2xx green, 3xx cyan, 4xx yellow, 5xx red

⚙️ Takeover Detection

CNAMERecon Pro includes detection for:

Service	Fingerprints
AWS	amazonaws.com, cloudfront.net
Netlify	netlify.app, netlify.com, netlifyglobalcdn.com
GitHub Pages	github.io
Azure	azurewebsites.net
Heroku	herokuapp.com
Fastly	fastly.net
Google Cloud	storage.googleapis.com

Error signatures are used to detect if the service is unclaimed, increasing accuracy.

🚀 Advanced Features

Ctrl+C clean termination with thread-safe shutdown

Filter by HTTP status for targeted results

Export professional reports (JSON & CSV)

Color-coded terminal output for easy review

📌 Planned Improvements

Automatic screenshot capture of takeover pages

--only-takeover flag for concise output

Markdown report generation for HackerOne/Bugcrowd submissions

Integration with subfinder or amass for automated subdomain discovery

📝 License

MIT License © 2026
You are free to use, modify, and distribute this tool.
