import json
import argparse
import sys
import os
import requests
import logging

from tqdm import tqdm

# Define your API keys and base URL
myAccessKey = os.environ.get('TENABLE_ACCESS_KEY')
mySecretKey = os.environ.get('TENABLE_SECRET_KEY')

def downloadPlugins(limit, progress):
    if limit < 1000 :
        print(f"results size of {limit} is below the default, ignoring and using the default limit of 1000")
        resultSize = 1000
    else: resultSize = limit
    initUrl = f"https://cloud.tenable.com/plugins/plugin?size={resultSize}"
    headers = {
        "accept": "application/json",
        "X-ApiKeys": f"accessKey={myAccessKey};secretKey={mySecretKey}"
    }
    response = json.loads(requests.get(initUrl, headers=headers).text)
    if resultSize: items_per_page = resultSize
    else: items_per_page = 1000
    number_of_pages = (response['total_count'] + items_per_page - 1) // items_per_page
    print(f"Based on the result size, downloading {number_of_pages} pages of plugin data. This may take a moment.")
    plugin_cve_list = {"data": {"plugin_cve_xref":[{'family':"pluginFamily","id":0, "cve":[]}]}}
    page = 1
    if progress == True:
        with tqdm(total=number_of_pages, desc="Downloading pages", unit="page") as pbar:
            while page <= number_of_pages:
                workUri = f"{initUrl}&page={page}"
                fullResponse = requests.get(workUri, headers=headers)
                response = json.loads(fullResponse.text)
                for PID in response['data']['plugin_details']:
                    pluginFamily = PID['family_name']
                    pluginID = PID['id']
                    cveList = PID['attributes']['cve']
                    plugin_cve_list['data']['plugin_cve_xref'].append({'family':pluginFamily, 'id':pluginID, 'cve':cveList})
                page += 1
                pbar.update(1)
    else:
        while page <= number_of_pages:
            workUri = f"{initUrl}&page={page}"
            fullResponse = requests.get(workUri, headers=headers)
            response = json.loads(fullResponse.text)
            for PID in response['data']['plugin_details']:
                pluginFamily = PID['family_name']
                pluginID = PID['id']
                cveList = PID['attributes']['cve']
                plugin_cve_list['data']['plugin_cve_xref'].append({'family':pluginFamily, 'id':pluginID, 'cve':cveList})
            page += 1
    print("Download complete...")
    return(plugin_cve_list)

def find_plugins_by_cves_json(cve_list, jsonFile):
    cvePluginList = []
    with open(jsonFile, 'r') as f:
        pluginData = json.load(f)
    for cve in cve_list:
        for plugin in pluginData['data']['plugin_cve_xref']:
            if cve in plugin['cve']: 
                cvePluginList.append(plugin['id'])
    cvePluginList = sorted(set(cvePluginList))
    return(cvePluginList)


def main(argv):
    parser = argparse.ArgumentParser(description='Prep or Query the local Tenable Plugin cache')
    parser.add_argument('--dbfile', required=True, default='tenable_plugins.json', help='The filename to use for the JSON formatted database')
    parser.add_argument('--init', required=False, default=False, action='store_true', help='Tells the script to wipe and replace the plugin cache. This should be run periodically')
    parser.add_argument('--progress', required=False, default=False, action='store_true', help='pretty progress indicator for downloads')
    parser.add_argument('--count', required=False, default=1000, help="Desired number of records per fetch, determines number of pages to download. Defaults to 1000 with a limit of 10000")
    args = parser.parse_args()

    if myAccessKey == None:
        print('You must supply your API Key and Secret as OS environment variables')
        exit()
    progressBar = False
    if args.progress == True:
        progressBar = args.progress
    
    jsonFile = args.dbfile
    if args.init == True:
        pluginData = downloadPlugins(limit=int(args.count), progress=progressBar)
        with open(jsonFile, 'w') as f:
            json.dump(pluginData, f, indent=4)

if __name__ == "__main__":
   main(sys.argv[1:])
