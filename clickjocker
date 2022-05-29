#!/usr/bin/env python3
import random
import sys
import requests
import argparse
from concurrent.futures import ThreadPoolExecutor


parser = argparse.ArgumentParser(description='Developed By elitebaz')
parser.add_argument('-d', '--domain', type=str, metavar='', help="Domain to scan.")
parser.add_argument('-v', '--verbose', action='store_true', help="Turn on stdout and print details.")
parser.add_argument('-l', '--list', type=str, metavar='', help="Path to list of domains to scan.")
parser.add_argument('-t', '--threads', type=int, metavar='', help="Number of threads.")
parser.add_argument('-o', '--output', type=str, metavar='', help="Path to the output list of vulnerable domains.")

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

number_of_threads = 5


def print_to_stdout(*a):
    """outputs to stdout"""
    print(*a, file=sys.stdout)


def url_format(domain):
    """:returns fixed format of url or false if url is not fixable"""
    try:
        # check for http first
        if "http://" not in domain:
            # check for https if http is not found
            if "https://" not in domain:
                # add http;// if both not found
                domain = "http://" + domain

        return domain.rstrip()

    except Exception as e:
        if args.verbose:
            print(e)
        return -1


def scan_url_for_clickjacking_vuln(url):

    try:
        vuln = url

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


def threaded_scan(url_list, threads):
    futures_list = []
    # start Thread Pool Executor with n workers
    with ThreadPoolExecutor(max_workers=number_of_threads) as executor:
        # loop through domains list
        for url in url_list:
            # create futures
            url = url_format(url)
            if url != -1:
                futures = executor.submit(scan_url_for_clickjacking_vuln, url)
                # append futures to futures list
                futures_list.append(futures)
        # loop through futures list
        for future in futures_list:
            try:
                is_vuln = future.result(timeout=60)
                # check if url is vulnerable
                if is_vuln != -1 and is_vuln is not False:
                    if args.verbose:
                        print(f"[+] {is_vuln} is vulnerable to clickjacking")
                        print(f"[+] Creating POC for {is_vuln}")
                    else:
                        print_to_stdout(is_vuln)
                    # generate PoC
                    generate_poc(is_vuln)
            except Exception as e:
                print(e)


def main():

    # check and fix url format
    global number_of_threads
    list_to_scan = []

    if args.threads:
        number_of_threads = args.threads

    if args.domain:
        list_to_scan.append(url_format(args.domain))

    elif args.list:
        with open(args.list, "r") as list_file:
            list_to_scan = list_file.readlines()
    else:
        list_to_scan = sys.stdin

    threaded_scan(list_to_scan, number_of_threads)


if __name__ == "__main__":
    main()
