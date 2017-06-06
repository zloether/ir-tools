#!/usr/bin/python
# get_related_hashes.py
# sample malicious hash: db349b97c37d22f5ea1d1841e3c89eb4

# import modules
from sys import argv
import requests, re, time

def get_related_hashes(input_hash, output=False):

    #--------------------------------------------------------------------------
    # global variables
    #--------------------------------------------------------------------------
    # https://www.virustotal.com/en/documentation/public-api/#audience
    apiKey = 'insert_virustotal_api_key_here'
    
    related_hashes = [] # initialize list
    api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apiKey, 'resource': input_hash_value}
    headers = {"Accept-Encoding": "gzip, deflate",}

    #--------------------------------------------------------------------------
    # make API request to look up input_hash_value
    #--------------------------------------------------------------------------
    response = requests.get(api_url, params=params, headers=headers)
    json_response = response.json()

    permalink = json_response['permalink']

    #--------------------------------------------------------------------------
    # make web request and parse out related hashes
    #--------------------------------------------------------------------------
    related_response = requests.get(permalink)

    regex_pattern = r'<a\Wtarget="\_blank\"\Whref="/en/file/[0-9a-f]+/analysis/">'

    matches = re.findall(regex_pattern, related_response.text, re.IGNORECASE)

    for item in matches: # iterate through response
        related_hashes.append(item.split("/")[3])

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
    result_hashes = [] # initialize return list

    for item in related_hashes:
        params = {'apikey': apiKey, 'resource': item}
        response = requests.get(api_url, params=params, headers=headers)
        try:
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

    get_related_hashes(input_hash_value, True)
