# Tenable API examples

Recently we had a need to interact with the Tenable.IO Vulnerability Management UI and found that, while feature rich, the experience was rather cludgy and slow.  Additionally, some tasks were unnecessarily tedious.  The following scripts are a short collection of some of the work I did to help automate creating remediation scans based on CVE notifications from CISA.

The full Tenable API doc is available [here](https://developer.tenable.com/reference/navigate)


## download_plugin_data.py
This script is used to create a local copy of the Tenable Plugin database.  It's only necessary because I could not find a cleaner way to filter plugins.  If you find another method, I'm all ears.  The result of running this script is to have a plugin and CVE cross reference that you can query to find relevant plugins based on published CVE numbers.

##
There is a bit of a pre-requisite to define the UUID for Credentials stored in Tenable.  You can locate the UUID by requesting [List Managed Credentials](https://developer.tenable.com/reference/credentials-list)

## create_scan.py: 
Once you have a local copy of the plugin database, you can create scans based on the CVE ID


## rerun_scan.py: (placeholder)
essentially the same as the previous, but you'll need to take the scan template ID from the create_scan.py and pass it into the rerun_scan.py as an arg

## export_report.py: (placeholder)
Another one that should be fairly obvious, take a specific template and scan ID and generate an HTML output report from the referenced scan.