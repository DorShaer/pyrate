import re
import os
import sys
import time
import secrets
import asyncio
import aiohttp
import requests
import argparse
from tqdm import tqdm
from texttable import Texttable
from termcolor import colored

# Author: Dor Shaer
# Version: 1.2
#
# This script sends HTTP requests to a specified URL at a specified rate and
# reports the status codes of the responses.



#Test for python version
if sys.version_info < (3, 9):
    sys.stdout.write("Sorry, pyrate requires Python 3.9 or higher\n")
    sys.exit(1)


# Set up argument parser
parser = argparse.ArgumentParser()

parser.add_argument("--url", type=str, help="URL to send requests to")
parser.add_argument("--body", type=str, help="request body to send with each request")
parser.add_argument("--headers", type=str, nargs='+', help='headers to send with each request separated by space (example: "Content-Type: application/json" "Authorization: Bearer 12345")')
parser.add_argument("--log", action="store_true", help="save a log file locally in logs folder with the URL as the file name")
parser.add_argument("--method", type=str, help="HTTP method to use, example: --method POST")
parser.add_argument("--rate", type=int, default=5, help="number of requests per second, deafult is 5")
parser.add_argument("--verbose", action="store_true", help="print the response body for each request")

args = parser.parse_args()

print("###Simple Python Rate Limiting Tester###")
print("This tool will multiply the numebr of the threads by 60, so it can calculate\nthe number of requests availabe in 1 minute.\n")


# Set the number of requests to send per second
try:
    rate = args.rate
except ValueError:
    print(colored("Error: Invalid value for rate. Rate must be a positive integer.", 'red', attrs=['bold']))
    exit(1)

# Set the URL to send the requests to
url = args.url

#Get the external IP
r = requests.get("https://api.ipify.org")
ip = r.text
print(colored("[+] External IP: " + ip, 'green', attrs=['bold']))

# Calculate the total number of requests to send
num_requests = rate * 60
print(colored("[+] Total requests: " + str(num_requests), 'green', attrs=['bold']))
if not url:
    # Prompt the user to enter a URL
    url = input("Enter the URL to send requests to: ")
print(colored("[+] Testing " + url, 'green', attrs=['bold']))


# Extract the base name of the URL
url_file_name = re.search(r"https?://([^/\.]+)\.([^/]+)", url).group(1)


status_codes = {}
total_requests = 0


# Send the requests
async def send_request(method, request_body=None):
    global total_requests
    request_id = secrets.token_hex(3)  # Generate a unique ID for the request
    start_time = time.perf_counter()
    async with aiohttp.ClientSession() as session:
        try:
            # Parse the headers argument into a dictionary
            headers = {x.split(":")[0]: x.split(":")[1] for x in args.headers} if args.headers else {}

            # Send the request with the specified method and headers
            if request_body is not None:
                # Send the request with the specified request body
                async with session.request(method, url, headers=headers, data=request_body) as response:
                    response_id = secrets.token_hex(3)  # Generate a unique ID for the response
                    elapsed_time = time.perf_counter() - start_time
                    if args.verbose:
                        print(f"Request {request_id} sent. Response {response_id} received with status code {response.status} in {elapsed_time:.2f} seconds\n")
                    if response.status not in status_codes:
                        status_codes[response.status] = 1
                    else:
                        status_codes[response.status] += 1
                    total_requests += 1
            else:
                # Send the request without a request body
                async with session.request(method, url, headers=headers) as response:
                    response_id = secrets.token_hex(3)  # Generate a unique ID for the response
                    elapsed_time = time.perf_counter() - start_time
                    if args.verbose:
                        print(f"{method} Request {request_id} sent. Response {response_id} received with status code {response.status} in {elapsed_time:.2f} seconds\n")
                    if response.status not in status_codes:
                        status_codes[response.status] = 1
                    else:
                        status_codes[response.status] += 1
                    total_requests += 1

            if args.log:
                if not os.path.exists("./logs"):
                    os.makedirs("./logs")
                log_file_path = f"./logs/{url_file_name}"
                with open(log_file_path, "a") as log_file:
                    if args.verbose:
                        log_file.write(f"Response body:\n{response.text}\n")
                    log_file.write(f"{method} Request {request_id} sent. Response {response_id} received with status code {response.status} in {elapsed_time:.2f} seconds\n")
        
        except Exception as e:
            print(colored(f"Error: {e}", 'red', attrs=['bold']))
            total_requests += 1
            exit(1)

            if args.log:
                if not os.path.exists("./logs"):
                    os.makedirs("./logs")
                log_file_path = f"./logs/{url_file_name}"
                with open(log_file_path, "a") as log_file:
                    log_file.write(f"{method} Request {request_id} was sent, got error {e}\n")
            total_requests += 1

async def main(start_index=0):
    # Send the requests
    with tqdm(total=num_requests, bar_format="{l_bar}{bar} [{elapsed}<{remaining}, {rate_fmt}]") as pbar:
        for i in range(start_index, num_requests):
            await asyncio.gather(send_request(method=args.method, request_body=args.body))
            pbar.update(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        x = input(colored("Ctrl+C Detected, do you wish to stop the scan? [c] - continue , else press enter to quit", 'red', attrs=['bold']))
        if x.lower() == "c":
            asyncio.run(main())
        else:
            print(colored("Exiting... ", 'red', attrs=['bold']))
            exit()


    # Print results in a table with borders
    table = Texttable()
    table.add_rows([["Total Requests", "Status Code"]])
    for status_code, count in status_codes.items():
    	table.add_row([count, status_code])
    table.set_deco(Texttable.BORDER | Texttable.HEADER)
    print(table.draw())
