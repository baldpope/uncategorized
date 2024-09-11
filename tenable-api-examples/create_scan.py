import json
import argparse
import sys
import os
import logging
import time

import requests
from requests.auth import HTTPBasicAuth

# Define your API keys and base URL
myAccessKey = os.environ.get('TENABLE_ACCESS_KEY')
mySecretKey = os.environ.get('TENABLE_SECRET_KEY')


# stored credentials in Tenable.IO
LinuxCreds = ""         # UUID value of the SSH credentials in Teanble.IO
WindowsCreds = ""      # UUID value of the Windows credentials in Tenable.IO
myCredentials = { 
            "add": {
                "Host": {
                    "Windows": [
                        {
                            "id": WindowsCreds
                        }
                    ],
                    "SSH": [
                        {
                            "id": LinuxCreds
                        }
                    ]
                }
            }
        }

# uuid of the internal scanner
myScannerId = ""

# Tenable.IO template, we use this to create a baseline and then adjust based on the enabled plugins
TenableScannerTemplate = "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66"

# Troubleshooting Credentialed Scans
# https://community.tenable.com/s/article/Useful-plugins-to-troubleshoot-credential-scans?language=en_US
baseline_windows = [24269,10394,10400,10428,57033,20811,26921,34252,35703,35704,24272,19506,10400,10428,13855,57033]
baseline_linux = [22869,12634,25221,33851,19506]
baseline_orable_db = [22073,10658,11219]
baseline_login_failures = [11149,21745,24786,26917,35705,35706]
baseline_local_auth = [979993,12634,10394,19762,73204,72816,57399,57400]
baseline_local_check = [21745,117886,117887]
baseline_third_party = [80860,65703,84231,84238,63062]
baseline_auth_issues = [102094,110695]
baseline_auth_status = [141118,110095,110385,104410,110723,117885]
baseline_master_plugins = baseline_windows + baseline_linux + baseline_orable_db + baseline_login_failures + baseline_local_auth + baseline_local_check + baseline_third_party + baseline_auth_issues + baseline_auth_status

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


def createScan(cve, scan_name, targets, plugins):
    url = "https://cloud.tenable.com/scans/remediation"
    myDescription = f'A plugin specific scan based on the following CVEs: {cve}'
    myTargets = targets
    myPlugins = plugins
    payload = {
        "settings": {
            "name": scan_name,
            "description": myDescription,
            "scanner_id": myScannerId,
            "text_targets": myTargets,
            "acls": [
                {
                    "permissions": 16,
                    "type": "default"
                }
                ]
        },
        "credentials": myCredentials,
        "uuid": TenableScannerTemplate,
        "enabled_plugins": myPlugins
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": f"accessKey={myAccessKey};secretKey={mySecretKey}"
    }
    response = json.loads(requests.post(url, json=payload, headers=headers).text)
    return(response)

def launchScan(scanid):
    # Use the Tenable's API to launch the scan
    url = f"https://cloud.tenable.com/scans/{scanid}/launch"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": f"accessKey={myAccessKey};secretKey={mySecretKey}"
    }
    response = requests.post(url, headers=headers)
    # Check if the request was successful
    if response.status_code == 200:
        message = f"Scan {scanid} launched successfully with scan ID {json.loads(response.text)}"
    else:
        message = f"Error: {response.status_code}, {response.text}"
    print(message)
    return(json.loads(response.text))

def get_scan_history_id(scanID, scanUUID):
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": f"accessKey={myAccessKey};secretKey={mySecretKey}"
    }
    url = f"https://cloud.tenable.com/scans/{scanID}/history?exclude_rollover=true"
    response = json.loads(requests.get(url, headers=headers).text)
    for scan in response['history']:
        if scan['scan_uuid'] == scanUUID:
            scanHistoryId = scan['id']
    return(scanHistoryId)


def main(argv):
    parser = argparse.ArgumentParser(description='Create and Launch new Remediation Scan')
    parser.add_argument('--dbfile', required=True, default='tenable_plugins.json', help='The filename to use for the JSON formatted database')
    parser.add_argument('--cve', required=True, help='CVEs in CSV format within quotes. EX: "CVE-2024-38080, CVE-2024-12345"')
    parser.add_argument('--targets', required=True, help='IP Ranges or individual IPs to scan. EX: 192.168.2.0/24, 192.168.11.30')
    parser.add_argument('--name', required=True, help='Scan name, something unique.')
    args = parser.parse_args()

    if myAccessKey == None:
        sys.exit('You must supply your API Key and Secret as OS environment variables')


    myCVE = args.cve.replace(' ','').split(',')
    additional_plugins = find_plugins_by_cves_json(cve_list=myCVE,jsonFile=args.dbfile)
    all_plugins = baseline_master_plugins + additional_plugins
    scanResponse = createScan(cve=args.cve, scan_name=args.name, targets=args.targets, plugins=all_plugins)
    launchResponse = launchScan(scanid=scanData['scanID'])
    historyID = get_scan_history_id(scanID=scanData["scanID"], scanUUID=launchResponse['scan_uuid'])

    print(f"The scan has been created with UUID {scanResponse['scan']['uuid']}")
    print(f"The scan has been created with ID {scanResponse['scan']['id']}")
    print(f"The scan was launched with scan ID {launchResponse}")
    print(f"The history ID for this scan is {historyID}")

if __name__ == "__main__":
   main(sys.argv[1:])