🛡️

Advanced Subdomain CNAME Scanner & Takeover Verifier

CNAMERecon Pro is a professional bug bounty and pentesting tool for scanning domains and subdomains, detecting CNAME records, verifying potential subdomain takeovers, and providing colorful, actionable output.

🖌️ Screenshot Preview

<img width="1777" height="734" alt="image" src="https://github.com/user-attachments/assets/833c54ed-f732-4a1a-9c39-e768ddffad73" />


🧠 Features

✅ Scan single or multiple domains from a file

✅ Resolve CNAME records and detect hosting services:

AWS, Netlify (+ netlifyglobalcdn.com), GitHub Pages, Azure, Heroku, Fastly, Google Cloud

✅ HTTP request verification with status codes

✅ Detect subdomain takeovers using error response fingerprints

✅ Filter output by HTTP status (--status 404)

✅ Export results to JSON and CSV

✅ Colorful terminal output for easy triage

✅ Thread-safe shutdown and clean Ctrl+C exit

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

Scan multiple subdomains:
python3 cnamercon_pro.py -f subdomains.txt

Filter results by HTTP status:
python3 cnamercon_pro.py -f subdomains.txt --status 404

Save output to JSON & CSV:
python3 cnamercon_pro.py -f subdomains.txt -o output/results

Multi-threading:
python3 cnamercon_pro.py -f subdomains.txt -t 20

🖌️ Output Example
[+] test.example.com                     → test.netlifyglobalcdn.com          | Netlify      | HTTP 404 | LIKELY TAKEOVER CONFIRMED
[+] app.example.com                      → app.github.io                      | GitHub Pages | HTTP 200 | POSSIBLE
[-] old.example.com                      → No CNAME


Red = Likely takeover

Green = Safe or possible

HTTP status code color-coded: 2xx green, 3xx cyan, 4xx yellow, 5xx red

⚙️ Takeover Detection

CNAMERecon Pro uses real error signatures for detection:

Service	Fingerprints
AWS	amazonaws.com, cloudfront.net
Netlify	netlify.app, netlify.com, netlifyglobalcdn.com
GitHub Pages	github.io
Azure	azurewebsites.net
Heroku	herokuapp.com
Fastly	fastly.net
Google Cloud	storage.googleapis.com
🚀 Advanced Features

Ctrl+C clean termination

Filter results by HTTP status

Export professional JSON/CSV reports

Color-coded terminal output for easy review

📌 Planned Improvements

Automatic screenshot capture of takeover pages

--only-takeover flag for concise output

Markdown report generator for HackerOne/Bugcrowd

Integration with subfinder / amass

📝 License

MIT License © 2026
