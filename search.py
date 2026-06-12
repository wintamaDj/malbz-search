# added:
# - api authkey field
# - better data and error handling for search_mb
# - added timeout options

import argparse
import requests
from time import sleep
import json
import os

#cli commands
parser = argparse.ArgumentParser(description="MalwareBazaar Advanced Search")
parser.add_argument("-s", "--search", type=str, help="Search String")
parser.add_argument("-l", "--limit", default=10, type=int, help="Upper limit of number of hashes to pull per search (default: 10) (max: 1000)")
parser.add_argument("--get-file", type=str, help="download this file hash")
parser.add_argument("--download-all", action="store_true", help="Download all files from a search and put them in a directory called 'samples'")
parser.add_argument("-t", "--timeout", default=60, type=int, help="Set timeout for requests in seconds (default: 60)")

args = parser.parse_args()
search_string = args.search
limit = args.limit
get_file = args.get_file
download_all = args.download_all
ttl = args.timeout
sleep_t = 10 #seconds

#api settings
api_url = "https://mb-api.abuse.ch/api/v1/"
api_key = os.environ.get("MALBZ_AUTH")  # remember to set env var
if not api_key:
    print("[!] MALBZ_AUTH environment variable not set")
    exit(1)
headers = {"Auth-Key": api_key}

#functions
def download_hash(hash):
    request_data = {
        "query": "get_file",
        "sha256_hash": str(hash).lower()
    }
    download_request = requests.post(
        url=api_url, 
        data=request_data,
        headers=headers,
        timeout=ttl)
    with open(str(hash) + "_pw_infected.zip", "wb") as f:
        f.write(download_request.content)

def convert_search_string(search_string):
    key_conversion = {
        "tag": "get_taginfo",
        "file_type": "get_file_type",
        "signature": "get_siginfo",
        "clamav": "get_clamavinfo",
        #"yara": "get_yarainfo", # not working
        "serial_number": "get_certificate",
        #"issuer_cn": "get_issuer", # not supported as it commonly includes spaceses
        "imphash": "get_imphash",
        "tlsh": "get_tlsh",
        "telfhash": "get_telfhash",
        "gimphash": "get_gimphash",
        "dhash_icon": "get_dhash_icon"
    }
    filters = search_string.split(" ")
    filters_coverted = []
    
    for filter in filters:
        split_filter = filter.split(":")
        k = split_filter[0]
        
        try:
            q = key_conversion[split_filter[0]]
        except KeyError:
            print(f"[!] {k} not a valid search operator")
            return
        
        v = split_filter[1]
        kv = {
            'query': q,
            k: v,
            'limit': limit
        }
        filters_coverted.append(kv)
    return filters_coverted

def search_mb(filters_coverted):
    success_list = []
    errors = []

    for filter in filters_coverted:
        print(f"[+] Parsing {filter}")

        #POST request
        try:    
            mb_request = requests.post(
                url=api_url, 
                data=filter, 
                headers=headers,
                timeout=ttl)
        except requests.exceptions.Timeout:
            errors.append(f"Request has timed out for {filter}. Consider increasing the timeout for slower connections")
            continue
        
        #parse JSON
        try:
            mb_response = json.loads(mb_request.text)
        except json.decoder.JSONDecodeError:
            errors.append(f"JSON Failed To Load for {filter}: {mb_request.text}")
            continue

        # debug to see api struct
        # print("\nAPI Structure:")
        # print(json.dumps(mb_response, indent=2))
        
        #get return_status
        return_status = str(mb_response.get('query_status', ''))
        if return_status != "ok":
            errors.append(f"Search operation Failed for {filter}: {mb_request.text}")
            continue
        
        #accept data
        data = mb_response.get("data", [])
        if not data:
            errors.append(f"No data key returned for {filter}: {mb_request.text}")
            continue
        success_list.append(data)
        
        print(f"[~] sleeping for {sleep_t}s to avoid getting dropped")
        sleep(sleep_t)
    return success_list, errors

def parse_results(data):
    hashes = []
    
    for result_set in data:
        for result in result_set:
            file_hash = str(result["sha256_hash"])
            hashes.append(file_hash)
    matches = set()
    
    for file_hash in hashes:
        if hashes.count(file_hash) == len(data): # number of sighting = number of searches
            matches.add(file_hash)
    
    if len(matches) == 0:
        print("\n[+] No Matches Found")
    elif len(matches) > 0:
        print(f"\n[+] Found {str(len(matches))} matches")
    
    #download
    if download_all:
        print("[+] Downloading Files to samples/")

    if len(matches) > 0:
        for hash in matches:
            print(f"[+] SHA256: {hash}")
            
            if download_all:
                try:
                    os.mkdir("samples")
                except FileExistsError:
                    pass
                
                os.chdir("samples")
                download_hash(hash)
                os.chdir("../")
        
        if download_all:
            print("[+] Finished Downloading Files")

def main():
    if get_file and search_string:
        print("[!] Cannot use --get-hash and --search at the same time")
        return
    
    if get_file:
        download_hash(get_file)
    
    if search_string:
        print(f"[+] Searching {search_string}")
        filters_coverted = convert_search_string(search_string)

        data, errors = search_mb(filters_coverted)
        for err in errors:
            print(f"\n[!] {err}")
        if data:
            parse_results(data)

main()