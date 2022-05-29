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
./clickjocker --help
```
```commandline
usage: clickjocker [-h] [-d] [-v] [-l] [-t] [-o]

Developed By elitebaz

optional arguments:
  -h, --help       show this help message and exit
  -d , --domain    Domain to scan.
  -v, --verbose    Turn on stdout and print details.
  -l , --list      Path to list of domains to scan.
  -t , --threads   Number of threads.
  -o , --output    Path to the output list of vulnerable domains.
```

## Example

Take single domain as input as argument
```commandline
$ ./clickjocker.py -v -d example.com

[+] http://example.com is vulnerable to clickjacking
[+] Creating POC for http://example.com
```

Take input from stdin
```commandline
$ cat hosts.txt | ./clickjocker

http://example.com
...
```

Take list file as input
```commandline
$ ./clickjocker.py -l hosts.txt

http://example.com
...
```
## Local Testing

You can test the ClickJacking vulnerability on this [awesome lab](https://github.com/auth0-blog/clickjacking-sample-app).

## Disclaimer

This tool is only for educational purposes, and I am not responsible for using this tool in any illegal activities.
