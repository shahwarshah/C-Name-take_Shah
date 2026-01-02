#!/usr/bin/env python3

import argparse
import dns.resolver
import json
import csv
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

# ---------------- INIT ---------------- #
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# ---------------- TAKEOVER DATABASE ---------------- #
FINGERPRINTS = {
    "Aftership": ["aftership.com"],
    "AgileCRM": ["agilecrm.com"],
    "Aha": ["aha.io"],
    "Airee": ["airee.ru"],
    "Anima": ["animaapp.io"],
    "AnnounceKit": ["announcekit.app"],
    "AWS S3": ["s3.amazonaws.com", "amazonaws.com", "cloudfront.net"],
    "BigCartel": ["bigcartel.com"],
    "Bitbucket": ["bitbucket.io"],
    "CampaignMonitor": ["campaignmonitor.com"],
    "Canny": ["canny.io"],
    "Cargo": ["cargocollective.com"],
    "Clever": ["clever-cloud.com"],
    "Flexbe": ["flexbe.io"],
    "Framer": ["framerusercontent.com"],
    "Frontify": ["frontify.com"],
    "Gemfury": ["gemfury.com"],
    "GetResponse": ["getresponse.com"],
    "Ghost": ["ghost.io"],
    "GitBook": ["gitbook.io"],
    "GitHub Pages": ["github.io"],
    "GoHire": ["gohire.io"],
    "GreatPages": ["greatpages.io"],
    "HatenaBlog": ["hatenablog.com"],
    "HelpDocs": ["helpdocs.io"],
    "HelpJuice": ["helpjuice.com"],
    "Helprace": ["helprace.com"],
    "HelpScout": ["helpscoutdocs.com"],
    "HubSpot": ["hubspot.com"],
    "Intercom": ["intercom.help"],
    "JazzHR": ["jazzhr.com"],
    "JetBrains": ["youtrack.cloud"],
    "Kinsta": ["kinsta.com"],
    "LaunchRock": ["launchrock.com"],
    "Leadpages": ["leadpages.com"],
    "Mashery": ["mashery.com"],
    "Meteor": ["meteor.com"],
    "Netlify": ["netlify.app", "netlify.com", "netlifyglobalcdn.com"],
    "Ngrok": ["ngrok.io"],
    "Pagewiz": ["pagewiz.com"],
    "Pantheon": ["pantheon.io"],
    "Pingdom": ["pingdom.com"],
    "Proposify": ["proposify.com"],
    "ReadMe": ["readme.io"],
    "ReadTheDocs": ["readthedocs.io"],
    "RedirectPizza": ["redirect.pizza"],
    "Shopify": ["myshopify.com"],
    "Short.io": ["short.io"],
    "SimpleBooklet": ["simplebooklet.com"],
    "SmartJobBoard": ["smartjobboard.com"],
    "SmugMug": ["smugmug.com"],
    "Softr": ["softr.io"],
    "Sprintful": ["sprintful.com"],
    "Squadcast": ["squadcast.com"],
    "Strikingly": ["strikinglydns.com"],
    "Surge": ["surge.sh"],
    "SurveyGizmo": ["surveygizmo.com"],
    "SurveySparrow": ["surveysparrow.com"],
    "Tave": ["tave.com"],
    "Teamwork": ["teamwork.com"],
    "Tilda": ["tilda.cc"],
    "Uberflip": ["uberflip.com"],
    "Uptime": ["uptime.com"],
    "UptimeRobot": ["uptimerobot.com"],
    "UserVoice": ["uservoice.com"],
    "Vend": ["vendhq.com"],
    "Wasabi": ["wasabisys.com"],
    "Wishpond": ["wishpond.com"],
    "Wix": ["wixsite.com"],
    "WordPress": ["wordpress.com"],
    "Worksites": ["worksites.net"],
    "Wufoo": ["wufoo.com"],
    "Zendesk": ["zendesk.com"],
    # ---------------- AZURE ---------------- #
    "Microsoft Azure": [
        "azure-api.net",
        "azure-mobile.net",
        "azurecontainer.io",
        "azurecr.io",
        "azuredatalakestore.net",
        "azureedge.net",
        "azurefd.net",
        "azurehdinsight.net",
        "azurewebsites.net",
        "azurewebsites.windows.net",
        "blob.core.windows.net",
        "cloudapp.azure.com",
        "database.windows.net",
        "redis.cache.windows.net",
        "search.windows.net",
        "servicebus.windows.net",
        "trafficmanager.net",
        "visualstudio.com",
        "web.core.windows.net"
    ]
}

# ---------------- ERROR SIGNATURES ---------------- #
ERROR_SIGNATURES = {
    "Netlify": ["not found", "no such site", "site not found"],
    "GitHub Pages": ["there isn't a github pages site here", "repository not found"],
    "AWS S3": ["the request could not be satisfied", "bad request", "no such bucket"],
    "Airee": ["ошибка 402"],
    "Anima": ["the page you were looking for does not exist"],
    "Bitbucket": ["repository not found"],
    "CampaignMonitor": ["trying to access your account"],
    "Canny": ["company not found", "no such company"],
    "Cargo": ["404 not found"],
    "Frontify": ["404 - page not found"],
    "Gemfury": ["404: this page could not be found"],
    "GetResponse": ["lead generation has never been easier"],
    "Ghost": ["site unavailable", "failed to resolve dns path"],
    "HatenaBlog": ["404 blog is not found"],
    "HelpJuice": ["could not find what you're looking for"],
    "Helprace": ["http_status=301"],
    "Ngrok": ["tunnel .* not found"],
    "Pantheon": ["404 error unknown site!"],
    "Pingdom": ["couldn't find the status page"],
    "ReadMe": ["still working on making everything perfect"],
    "ReadTheDocs": ["the link you have followed or the url that you entered does not exist"],
    "Shopify": ["sorry, this shop is currently unavailable"],
    "Short.io": ["link does not exist"],
    "SmartJobBoard": ["job board website is either expired or its domain name is invalid"],
    "Strikingly": ["page not found"],
    "Surge": ["project not found"],
    "SurveySparrow": ["account not found"],
    "Tilda": ["please renew your subscription"],
    "Uberflip": ["the url you've accessed does not provide a hub"],
    "UptimeRobot": ["page not found"],
    "WordPress": ["do you want to register .*?\\.wordpress\\.com"],
    "Worksites": ["hello! sorry, but the website you’re looking for doesn’t exist"],
    # ---------------- AZURE ERRORS ---------------- #
    "Microsoft Azure": [
        "the resource you are looking for has been removed",
        "404 web site not found",
        "this azure web app has been stopped",
        "no such host is known",
        "the specified resource does not exist",
        "resource not found",
        "error 404"
    ]
}

# ---------------- UI ---------------- #
class ColorHelpFormatter(argparse.RawTextHelpFormatter):
    def start_section(self, heading):
        heading = f"{Fore.CYAN}{heading}{Style.RESET_ALL}"
        super().start_section(heading)

def banner():
    print(Fore.CYAN + r"""
   ____ _   _    _    __  __ _____ ____  _____ ____  ___  _   _
  / ___| \ | |  / \  |  \/  | ____|  _ \| ____/ ___|/ _ \| \ | |
 | |   |  \| | / _ \ | |\/| |  _| | |_) |  _|| |   | | | |  \| |
 | |___| |\  |/ ___ \| |  | | |___|  _ <| |__| |___| |_| | |\  |
  \____|_| \_/_/   \_\_|  |_|_____|_| \_\_____\____|\___/|_| \_|

        CNAMERecon Pro – Subdomain Takeover Recon
                     by Shahwar Shah
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
        except requests.RequestException:
            continue
    return None, ""

def check_error_signature(service, body):
    for sig in ERROR_SIGNATURES.get(service, []):
        if sig in body:
            return True
    return False

def resolve_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            cname = str(rdata.target).rstrip(".")
            service = detect_service(cname)
            status, body = fetch_http(domain)

            if status is None:
                takeover = "UNREACHABLE"
            elif status in [401, 403]:
                takeover = "NO"
            # ---------------- AZURE SPECIAL HANDLING ---------------- #
            elif service == "Microsoft Azure" and status in [404, 400] and check_error_signature(service, body):
                takeover = "LIKELY"
            elif check_error_signature(service, body):
                takeover = "LIKELY"
            else:
                takeover = "NO"

            return domain, cname, service, status, takeover

    except dns.resolver.NoAnswer:
        return domain, None, None, None, "NO"
    except dns.resolver.NXDOMAIN:
        return domain, "NXDOMAIN", None, None, "NO"
    except dns.exception.Timeout:
        return domain, "TIMEOUT", None, None, "UNREACHABLE"
    except Exception:
        return domain, "ERROR", None, None, "UNREACHABLE"

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

def print_result(domain, cname, service, status, takeover, filter_status, filter_cnames):
    if filter_status and status != filter_status:
        return
    if filter_cnames and cname not in filter_cnames:
        return

    if cname is None:
        print(f"{Fore.YELLOW}[-] {domain:<35} → No CNAME")
        return

    if cname in ["NXDOMAIN", "TIMEOUT", "ERROR"]:
        print(f"{Fore.RED}[!] {domain:<35} → {cname}")
        return

    sev = Fore.GREEN
    label = takeover

    if takeover == "LIKELY":
        sev = Fore.RED
        label += " TAKEOVER"
    elif takeover == "UNREACHABLE":
        sev = Fore.WHITE
    elif status in [401, 403]:
        label += " PROTECTED"

    print(
        f"{sev}[+] {domain:<35} → "
        f"{Fore.CYAN}{cname:<45} | "
        f"{service:<20} | "
        f"HTTP {color_status(status)} | {label}"
    )

# ---------------- MAIN ---------------- #
def main():
    parser = argparse.ArgumentParser(
        description="CNAMERecon Pro – Advanced Subdomain Takeover Scanner",
        formatter_class=ColorHelpFormatter
    )

    parser.add_argument("-d", "--domain", help="Single domain")
    parser.add_argument("-f", "--file", help="File with subdomains")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("-o", "--output", help="Output prefix")
    parser.add_argument("--status", type=int, help="Filter by HTTP status")
    parser.add_argument("--filter-cname", nargs="*", help="Filter by one or more CNAMEs (space separated)")

    args = parser.parse_args()
    banner()

    domains = []
    if args.domain:
        domains.append(args.domain.strip())
    if args.file:
        try:
            with open(args.file) as f:
                domains.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(Fore.RED + "[!] File not found")
            return

    if not domains:
        print(Fore.RED + "[!] No domains provided")
        return

    results = []
    executor = ThreadPoolExecutor(max_workers=args.threads)

    try:
        futures = [executor.submit(resolve_domain, d) for d in domains]
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            print_result(*r, args.status, args.filter_cname)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Interrupted by user (Ctrl+C)")
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(0)

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
                        "takeover": t
                    }
                    for d, c, s, sc, t in results
                ],
                jf,
                indent=2
            )

        with open(args.output + ".csv", "w", newline="") as cf:
            writer = csv.writer(cf)
            writer.writerow(["Domain", "CNAME", "Service", "HTTP Status", "Takeover"])
            writer.writerows(results)

        print(Fore.CYAN + f"\n[✓] Saved to {args.output}.json and {args.output}.csv")

# ---------------- ENTRY ---------------- #
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exiting cleanly.")
        sys.exit(0)
