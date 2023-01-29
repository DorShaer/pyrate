## 🔥 What is Pyrate?

pyrate project is designed to test the effectiveness of these measures by sending requests to a web application and checking whether they are blocked by the rate-limiting and WAF mechanisms. The code is using the asyncio library to handle concurrency and make many requests at the same time, which could help simulate real-world traffic more effectively.

## 📦 Installation

1. [Install Python](https://wiki.python.org/moin/BeginnersGuide/Download)
2. `git clone` this repo
3. `cd` into the repo
4. `pip install -r requirements.txt`

## 💡 Usage

The `pyrate` application takes few arguments:

1. `--url` - the URL to test
2. `--rate` - number of requests per second, deafult is 5
3. `--log` - save a log file locally in logs/ with the URL as the file name
4. `--body` - add a custom request body to send with each request, default is None
5. `--headers` - headers to send with each request separated by space
6. `--method` - HTTP method to use
7. `--verbose` - print the response body for each request
8. `--random-agent` - send a random user agent with each request
9. `--waf` - append '<script>alert(1)</script>' to the URL and trigger the WAF
10. `--waf-list` - list all available wafs
11. `--insecure` - bypass certificate checks

`python3 pyrate --url https://example.com/ --rate 1 --method POST --body "id=1" --headers "Content-Type: application/json" "Authorization:Bearer 12345" --waf`

```bash
❯ python3 pyrate.py --url https://brokencrystals.com --rate 1 
###Simple Python Rate Limiting Tester###
This tool will multiply the numebr of the threads by 60, so it can calculate
the number of requests availabe in 1 minute.

[info] External IP: X.X.X.X
[info] Total requests: 25
[info] Testing https://brokencrystals.com
[success] Detected WAF: Cloudflare WAF
100%|██████████████████████████████████████████████████ [00:16<00:00,  3.58it/s]
+------------------------------+
| Total Requests   Status Code |
+==============================+
| 25               200         |
+------------------------------+
[logging] debug files were saved in: ./logs/brokencrystals.log
```

All debug files will be saved to the `logs/[hostname]` folder.

## 🐋 Using Docker

1. git clone this repo
2. `cd` into the repo
3. `docker build -t pyrate .`
4. `docker run -it pyrate --url https://example.com/`

## 🏆 Contributors

- [Dor Shaer](https://github.com/DorShaer) - creator and maintainer

## 🙏 Credits
  All WAF signatures logic were taken from the awesome library wafalyzer
- https://github.com/NeuraLegion/wafalyzer 
