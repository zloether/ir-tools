#!/usr/bin/python
# virustotal_related_hashes.py
# sample malicious hash: db349b97c37d22f5ea1d1841e3c89eb4

# import modules
from sys import argv
import requests, re, time
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    bundled = True
except:
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
    bundled = False

def get_related_hashes(input_hash, verify=True, output=False):
    #--------------------------------------------------------------------------
    # global variables
    #--------------------------------------------------------------------------
    # https://www.virustotal.com/en/documentation/public-api/#audience
    apiKey = 'insert_virustotal_api_key_here'
    api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apiKey, 'resource': input_hash_value}
    headers = {"Accept-Encoding": "gzip, deflate",}
    if not verify:
        if bundled:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        else:
            urllib3.disable_warnings(InsecureRequestWarning)

    related_hashes = [] # initialize list

    #--------------------------------------------------------------------------
    # make API request to look up input_hash_value
    #--------------------------------------------------------------------------
    response = requests.get(api_url, params=params, headers=headers, verify=verify)
    try:
        json_response = response.json()
    except:
        print(response.status_code)
        print(reponse.text)
        exit()

    permalink = json_response['permalink']

    #--------------------------------------------------------------------------
    # make web request and parse out related hashes
    #--------------------------------------------------------------------------
    related_response = requests.get(permalink, verify=verify)

    regex_pattern = r'<a\Wtarget="\_blank\"\Whref="/en/file/[0-9a-f]+/analysis/">'

    try:
        matches = re.findall(regex_pattern, related_response.text, re.IGNORECASE)
    except:
        print(related_response.status_code)
        print(related_response.text)
        exit()

    for item in matches: # iterate through response
        related_hashes.append(item.split("/")[3]) # parse out the desired text

    #--------------------------------------------------------------------------
    # print expected time to completion
    #--------------------------------------------------------------------------
    minutes = int(len(matches) / 4)
    if minutes >= 1:
        print("Your request will take approximately " + str(minutes) \
                + " minutes to complete...")
        delay = 15
    else:
        delay = 0

    #--------------------------------------------------------------------------
    # make API requests for each related hash
    #--------------------------------------------------------------------------
    if not output:
        result_hashes = [] # initialize return list

    for item in related_hashes:
        try:
            params = {'apikey': apiKey, 'resource': item}
            response = requests.get(api_url, params=params, headers=headers, verify=verify)
            if output:
                print(response.json()[hash_type])
            else:
                result_hashes.append(response.json()[hash_type])
        except:
            print(response.text)
        time.sleep(delay)

    if not output:
        return result_hashes

if __name__ == "__main__":
    #--------------------------------------------------------------------------
    # get argument
    #--------------------------------------------------------------------------
    try:
        script, hash_type, input_hash_value = argv
    except:
        print("Usage: get_related_hashes.py <hash type> <hash>")
        print("This script takes two arguments:")
        print("1) <hash type> (options: md5, sha1, sha256)")
        print("2) <hash>")
        print("This script will lookup and provide a list of all related hashes" +\
                " using the provided hash type (e.g., md5, sha1, or sha256)")
        exit()

    get_related_hashes(input_hash_value, verify=True, output=True)
