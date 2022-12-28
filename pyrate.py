import re
import os
import sys
import asyncio
import aiohttp
import requests
import argparse
from tqdm import tqdm
from texttable import Texttable
from termcolor import colored

# Author: Dor Shaer
# Version: 1.0
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
parser.add_argument("--rate", type=int, default=5, help="number of requests per second, deafult is 5")
parser.add_argument("--log", action="store_true", help="save a log file locally in logs folder with the URL as the file name")

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



# Create a valid file name from the URL
url_file_name = re.sub(r"https?://", "", url)

status_codes = {}
total_requests = 0

async def send_request():
    global total_requests
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url) as response:
                if response.status in status_codes:
                    status_codes[response.status] += 1
                else:
                    status_codes[response.status] = 1
                if args.log:
                    if not os.path.exists("./logs"):
                        os.makedirs("./logs")
                    log_file_path = f"./logs/{url_file_name}"
                    with open(log_file_path, "a") as log_file:
                        log_file.write(f"Request was sent, got status code {response.status}\n")
                total_requests += 1

        #Catch exception if errors displayed
        except Exception as e:
            if "Error" in status_codes:
                status_codes["Error"] += 1
            else:
                status_codes["Error"] = 1
            if args.log:
                with open(f"/tmp/{url_file_name}", "a") as log_file:
                    log_file.write(f"Error occurred while sending request: {e}\n")

async def main():
    # Send the requests
    with tqdm(total=num_requests, bar_format="{l_bar}{bar} [{elapsed}<{remaining}, {rate_fmt}]") as pbar:
        for i in range(num_requests):
            await asyncio.gather(send_request())
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
