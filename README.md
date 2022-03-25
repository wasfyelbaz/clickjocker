# Clickjoker

Clickjoker is a python-based software that scans specific domain(s) for ClickJacking vulnerability and
automatically creates a POC file for the vulnerable domain(s).

## Installation
```commandline
git clone https://github.com/wasfyelbaz/clickjocker.git
cd clickjocker
pip3 install -r requirements.txt
```

## Usage
```commandline
python3 clickjocker.py --help
```
```commandline
usage: clickjocker.py [-h] -d  [-v] [-l] [-o]

Developed By elitebaz

optional arguments:
  -h, --help      show this help message and exit
  -d , --domain   Domain to scan.
  -v, --verbose   Turn on stdout and print details.
  -l , --list     Path to list of domains to scan.
  -o , --output   Path to the output list of vulnerable domains.
```

## Example

```commandline
$ python3 clickjocker.py -v -d example.com

[+] http://example.com is vulnerable to clickjacking
[+] Creating POC for http://example.com
```

## Local Testing

You can test the ClickJacking vulnerability on this [awesome lab](https://github.com/auth0-blog/clickjacking-sample-app).

## Disclaimer

This tool is only for educational purposes, and I am not responsible for using this tool in any illegal activities.