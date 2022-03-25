import requests
import argparse
import random

parser = argparse.ArgumentParser(description='Developed By elitebaz')
parser.add_argument('-d', '--domain', type=str, metavar='', required=True, help="Domain to scan.")
parser.add_argument('-v', '--verbose', action='store_true', help="Turn on stdout and print details.")
parser.add_argument('-l', '--list', type=str, metavar='', required=False, help="Path to list of domains to scan.")
parser.add_argument('-o', '--output', type=str, metavar='', required=False, help="Path to the output list of vulnerable domains.")

args = parser.parse_args()

user_agents = [
    "Mozilla/5.0 (Linux; Android 10; ELE-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Mobile Safari/537.36 EdgA/99.0.1150.46",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36 Unique/95.7.8946.47",
    "Mozilla/5.0 (Linux; Android 9; WP7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.73 Mobile Safari/537.36"
]

headers = {
    'Dnt': '1',
    'User-Agent': random.choice(user_agents),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch-Dest': 'document',
    'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
}

poc_html = """<html>
    <head><title>Clickjack test page</title></head>
    <body>
        <p>Website is vulnerable to clickjacking!</p>
        <iframe src="VULN_URL" width="1000" height="1000"></iframe>
    </body>
</html>
"""


def url_format(domain):
    """:returns fixed format of url or false if url is not fixable"""
    try:
        url = domain

        # check for http first
        if "http://" not in domain:
            # check for https if http is not found
            if "https://" not in domain:
                # add http;// if both not found
                url = "http://" + domain

        return url

    except Exception as e:
        if args.verbose:
            print(e)
        return -1


def scan_url_for_clickjacking_vuln(url):

    try:
        vuln = True

        response = requests.get(url, headers=headers, timeout=10)

        if "X-Frame-Options" in response.headers.keys():
            vuln = False
            if args.verbose:
                print(f"[-] X-Frame-Options found in response headers with value [ {response.headers['X-Frame-Options']} ]")

        if "Content-Security-Policy" in response.headers.keys() and "frame-ancestors" in response.headers["Content-Security-Policy"]:
            vuln = False
            if args.verbose:
                print(f"[-] Content-Security-Policy found in response headers with value [ {response.headers['Content-Security-Policy']} ]")

        if "Set-Cookie" in response.headers.keys() and "SameSite=Strict" in response.headers["Set-Cookie"]:
            vuln = False
            if args.verbose:
                print("[-] Set-Cookie found in response headers containing [ SameSite=Strict ]")

        return vuln

    except Exception as e:
        if args.verbose:
            print(e)
        return -1


def generate_poc(url):
    """generates poc from vuln url"""
    poc_name = url.split("/")[2] + ".html"
    with open(poc_name, "w") as poc:
        poc.write(poc_html.replace("VULN_URL", url))


def main():

    # check and fix url format
    url = url_format(args.domain)

    is_vuln = scan_url_for_clickjacking_vuln(url)

    if url != -1 and is_vuln != -1 and is_vuln != False:

        if args.verbose:
            print(f"[+] {url} is vulnerable to clickjacking")
            print(f"[+] Creating POC for {url}")
        else:
            print(url)

        generate_poc(url)


if __name__ == "__main__":
    main()
