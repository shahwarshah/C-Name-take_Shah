#!/usr/bin/env python3

import argparse
import dns.resolver
import json
import csv
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

# Init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# ---------------- CONFIG ---------------- #

FINGERPRINTS = {
    "AWS": ["amazonaws.com", "cloudfront.net"],
    "Netlify": ["netlify.app", "netlify.com", "netlifyglobalcdn.com"],
    "GitHub Pages": ["github.io"],
    "Azure": ["azurewebsites.net"],
    "Fastly": ["fastly.net"],
    "Heroku": ["herokuapp.com"],
    "Google Cloud": ["storage.googleapis.com"]
}

ERROR_SIGNATURES = {
    "Netlify": ["not found", "no such site", "site not found"],
    "GitHub Pages": ["there isn't a github pages site here", "repository not found"],
    "Azure": ["web site not found", "resource you are looking for has been removed"],
    "Heroku": ["no such app", "there's nothing here"],
    "Fastly": ["fastly error: unknown domain"],
    "AWS": ["the request could not be satisfied", "bad request"]
}

# ---------------- COLORFUL HELP ---------------- #

class ColorHelpFormatter(argparse.RawTextHelpFormatter):
    def start_section(self, heading):
        heading = f"{Fore.CYAN}{heading}{Style.RESET_ALL}"
        super().start_section(heading)

# ---------------- UI ---------------- #

def banner():
    print(Fore.CYAN + """
   ____ _   _    _    __  __ _____ ____  _____ ____  ___  _   _
  / ___| \\ | |  / \\  |  \\/  | ____|  _ \\| ____/ ___|/ _ \\| \\ | |
 | |   |  \\| | / _ \\ | |\\/| |  _| | |_) |  _|| |   | | | |  \\| |
 | |___| |\\  |/ ___ \\| |  | | |___|  _ <| |__| |___| |_| | |\\  |
  \\____|_| \\_/_/   \\_\\_|  |_|_____|_| \\_\\_____\\____|\\___/|_| \\_|
         CNAMERecon Pro – Subdomain Takeover Recon By Shahwar shah
    """ + Style.RESET_ALL)

# ---------------- CORE ---------------- #

def detect_service(cname):
    for service, patterns in FINGERPRINTS.items():
        for p in patterns:
            if p in cname:
                return service
    return "Unknown"


def fetch_http(domain):
    for scheme in ["https://", "http://"]:
        try:
            r = requests.get(
                scheme + domain,
                timeout=6,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "CNAMERecon-Pro"}
            )
            return r.status_code, r.text.lower()
        except Exception:
            continue
    return None, ""


def check_error_signature(service, body):
    if service in ERROR_SIGNATURES:
        for sig in ERROR_SIGNATURES[service]:
            if sig in body:
                return True
    return False


def resolve_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            cname = str(rdata.target).rstrip(".")
            service = detect_service(cname)

            status_code, body = fetch_http(domain)

            if service != "Unknown":
                vulnerable = check_error_signature(service, body)
                takeover = "LIKELY" if vulnerable else "POSSIBLE"
            else:
                takeover = "NO"

            return domain, cname, service, status_code, takeover

    except dns.resolver.NoAnswer:
        return domain, None, None, None, "NO"
    except dns.resolver.NXDOMAIN:
        return domain, "NXDOMAIN", None, None, "NO"
    except dns.exception.Timeout:
        return domain, "TIMEOUT", None, None, "NO"
    except Exception:
        return domain, "ERROR", None, None, "NO"

# ---------------- OUTPUT ---------------- #

def color_status(code):
    if code is None:
        return Fore.WHITE + "N/A"
    if 200 <= code < 300:
        return Fore.GREEN + str(code)
    if 300 <= code < 400:
        return Fore.CYAN + str(code)
    if 400 <= code < 500:
        return Fore.YELLOW + str(code)
    return Fore.RED + str(code)


def print_result(domain, cname, service, status_code, takeover, filter_status):
    if filter_status and status_code != filter_status:
        return

    if cname is None:
        print(f"{Fore.YELLOW}[-] {domain:<35} → No CNAME")
    elif cname in ["NXDOMAIN", "TIMEOUT", "ERROR"]:
        print(f"{Fore.RED}[!] {domain:<35} → {cname}")
    else:
        sev_color = Fore.RED if takeover == "LIKELY" else Fore.GREEN
        flag = f"{Fore.RED} TAKEOVER CONFIRMED" if takeover == "LIKELY" else ""
        print(
            f"{sev_color}[+] {domain:<35} → "
            f"{Fore.CYAN}{cname:<40} "
            f"| {service:<12} "
            f"| HTTP {color_status(status_code)} "
            f"| {takeover}{flag}"
        )

# ---------------- MAIN ---------------- #

def main():
    parser = argparse.ArgumentParser(
        description="CNAMERecon Pro – Advanced CNAME Takeover Scanner",
        formatter_class=ColorHelpFormatter
    )

    parser.add_argument("-d", "--domain", help="Scan a single domain")
    parser.add_argument("-f", "--file", help="File containing subdomains")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Output file prefix (json/csv)")
    parser.add_argument(
        "--status",
        type=int,
        help="Show only results matching HTTP status code (e.g. 404)"
    )

    args = parser.parse_args()

    banner()

    domains = []

    if args.domain:
        domains.append(args.domain.strip())

    if args.file:
        try:
            with open(args.file, "r") as f:
                domains.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(Fore.RED + "[!] Subdomain file not found")
            return

    if not domains:
        print(Fore.RED + "[!] No domains provided")
        return

    results = []
    executor = ThreadPoolExecutor(max_workers=args.threads)

    try:
        futures = [executor.submit(resolve_domain, d) for d in domains]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print_result(*result, args.status)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Scan interrupted by user (Ctrl+C). Exiting cleanly.")
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(0)

    finally:
        executor.shutdown(wait=True)

    if args.output:
        with open(args.output + ".json", "w") as jf:
            json.dump(
                [
                    {
                        "domain": d,
                        "cname": c,
                        "service": s,
                        "http_status": sc,
                        "takeover_status": t
                    }
                    for d, c, s, sc, t in results
                ],
                jf,
                indent=2
            )

        with open(args.output + ".csv", "w", newline="") as cf:
            writer = csv.writer(cf)
            writer.writerow(["Domain", "CNAME", "Service", "HTTP Status", "Takeover Status"])
            for row in results:
                writer.writerow(row)

        print(Fore.CYAN + f"\n[✓] Results saved to {args.output}.json and {args.output}.csv")

# ---------------- ENTRY ---------------- #

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Goodbye.")
        sys.exit(0)
