# pyrate

Python Rate Limit tester

## Installation

1. [Install Python](https://wiki.python.org/moin/BeginnersGuide/Download)
2. `git clone` this repo
3. `cd` into the repo
4. `pip install -r requirements.txt`

## Usage

The `pyrate` application takes a few arguments:

1. `--url` - The URL to test
2. `--rate` - umber of requests per second, deafult is 5
3. `--log` - save a log file locally in logs/ with the URL as the file name

`python3 pyrate --url https://example.com/`

```bash
❯ python3 pyrate.py --url https://brokencrystals.com --rate 1 
###Simple Python Rate Limiting Tester###
This tool will multiply the numebr of the threads by 60, so it can calculate
the number of requests availabe in 1 minute.

[+] External IP: X.X.X.X
[+] Total requests: 60
[+] Testing https://brokencrystals.com
100%|██████████████████████████████████████████████████ [00:16<00:00,  3.58it/s]
+------------------------------+
| Total Requests   Status Code |
+==============================+
| 60               200         |
+------------------------------+

```

Debug files will be saved to the `logs/[hostname]` folder.

### Using Docker

1. git clone this repo
2. `cd` into the repo
3. `docker build -t pyrate .`
4. `docker run -it pyrate --url https://example.com/`

## Contributors

- [Dor Shaer](https://github.com/DorShaer) - creator and maintainer
