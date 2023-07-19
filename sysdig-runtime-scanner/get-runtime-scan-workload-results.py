"""
  This python script will retrieve all runtime workload scanning results for the 
  passed api token. 

  The intent it to mimick the current runtime report functionality
  so that the result is a runtime report of what is running now.

  The report will not contain images without vulnerabilities.
  
  The report will only retrieve "workload" results and not "host" results.

  Author: Kendall Adkins
  Date July 11th, 2023
  Updated: July 19th, 2023

  TODO:
     - Look into updating the accepts column and/or adding a new image accepts column.
     - asset.type is not in the JSON output but it can be included in the query string as a filter
     - add support for Vuln Link column: report_row.append('TODO') ### "Vuln link"
     - add support for K8S POD count column: report_row.append('TODO') ### "K8S POD count"
     - add support for Risk accepted column: report_row.append('TODO') ### "Risk accepted")
     - api bug? periodically get a blank image pull string without a 404: result.metatdata.pullString
"""

import argparse
import logging
import sys
import urllib3
import json
import urllib.parse
from datetime import datetime
from datetime import timedelta
import math
import csv
import platform
import time
import csv
import os.path

# Setup logger
LOG = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

# Setup http client
#TODO tried timeout but it had no impact; investigate further
#timeout = urllib3.util.Timeout(connect=5.0, read=10.0)
#http_client = urllib3.PoolManager(timeout=timeout)
http_client = urllib3.PoolManager()

# Track number of http response codes
num_of_429 = 0
num_of_504 = 0

# Will be set by a passed arg
secure_url_authority = ""

# Define custom exceptions
class UnexpectedHTTPResponse(Exception):
    """Used when recieving an unexpected HTTP response"""

def _parse_args():

    args = None

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--secure_url_authority",
        required=True,
        type=str,
        action="store",
        help="authority component of secure url",
    )
    parser.add_argument(
        "--api_token",
        required=True,
        type=str,
        action="store",
        help="Sysdig Secure API Token",
    )
    parser.add_argument(
        "--csv_file_name",
        required=True,
        type=str,
        action="store",
        help="CSV output file name",
    )
    return parser.parse_args()

def main():

    try:

        # Parse the command line arguments
        args = _parse_args()
        global secure_url_authority
        secure_url_authority = args.secure_url_authority
        authentication_bearer = args.api_token
        csv_file_name = args.csv_file_name

        if os.path.isfile(csv_file_name):
            LOG.error(f"ERROR: The input csv file {csv_file_name} already exists!")
            raise SystemExit(-1)

        # Get the timestamp of this run
        now = datetime.now()
        current_datetime = now.strftime("%Y-%m-%d %H:%M")

        # Add the authentication header
        http_client.headers["Authorization"] = f"Bearer {authentication_bearer}"

        # Start performance counter
        pc_start = time.perf_counter()

        # Get the runtime workload scan results
        LOG.info(f"Retrieving the list of runtime workload scan results...")
        scan_results_list = _get_runtime_workload_scan_results_list()
        LOG.info(f"Found {len(scan_results_list)} total scan results.")
        
        if len(scan_results_list) == 0:
           LOG.info(f"No scan results found.")

        else:

            # Get the list of runtime workload scan results with vulnerabilities
            LOG.info(f"Searching for runtime workload scan results with vulnerabilities...")
            scan_results_list_with_vulns = _get_scan_results_list_with_vulnerabilties(scan_results_list)
            LOG.info(f"Found {len(scan_results_list_with_vulns)} scan results with vulnerabilities.")
            LOG.info(f"Found {len(scan_results_list) - len(scan_results_list_with_vulns)} scan results with no vulnerabilities.")

            # Get the image scan results for workloads with vulnerabilities
            LOG.info(f"Retrieving runtime scan results for images with vulnerabilities...")
            images_with_vulns_scan_results = _get_image_scan_results(scan_results_list_with_vulns)
            LOG.info(f"Found {len(images_with_vulns_scan_results)} runtime image scan results.")

            # Gather the report data
            report_data = _gather_report_data(scan_results_list_with_vulns, images_with_vulns_scan_results)
            
            # Save the report data to a csv file
            with open(csv_file_name, 'w') as csv_output_file:
                write = csv.writer(csv_output_file)
                write.writerows(report_data)

        #end if

        # End performance counter
        pc_end = time.perf_counter()
        elapsed_seconds = pc_end - pc_start
        execution_time = "{}".format(str(timedelta(seconds=elapsed_seconds)))
        LOG.info(f"Elapsed execution time: {execution_time}")

        LOG.info(f"HTTP Response Code 429 occured: {num_of_429} times.")
        LOG.info(f"HTTP Response Code 504 occured: {num_of_504} times.")

        LOG.info(f'Request for runtime scan results complete.')

    except Exception as e:
        LOG.critical(e)
        LOG.error(f'Request to download runtime results failed.')
        raise SystemExit(-1)

def _gather_report_data(scan_results_list_with_vulns, images_with_vulns_scan_results):

    report_data = []

    report_headers = []
    report_headers.append("Vulnerability ID")
    report_headers.append("Severity")
    report_headers.append("Package name")
    report_headers.append("Package version")
    report_headers.append("Package type")
    report_headers.append("Package path")
    report_headers.append("Image")
    report_headers.append("OS Name")
    report_headers.append("CVSS version")
    report_headers.append("CVSS score")
    report_headers.append("CVSS vector")
    report_headers.append("Vuln link")
    report_headers.append("Vuln Publish date")
    report_headers.append("Vuln Fix date")
    report_headers.append("Fix version")
    report_headers.append("Public Exploit")
    report_headers.append("K8S cluster name")
    report_headers.append("K8S namespace name")
    report_headers.append("K8S workload type")
    report_headers.append("K8S workload name")
    report_headers.append("K8S container name")
    report_headers.append("Image ID")
    report_headers.append("K8S POD count")
    report_headers.append("Package suggested fix")
    report_headers.append("In use")
    report_headers.append("Risk accepted")

    report_data.append(report_headers)
    
    for result in scan_results_list_with_vulns:

        result_id = result["resultId"]

        kubernetes_cluster_name = result["scope"]["kubernetes.cluster.name"]
        kubernetes_namespace_name = result["scope"]["kubernetes.namespace.name"]
        kubernetes_pod_container_name = result["scope"]["kubernetes.pod.container.name"]
        kubernetes_workload_name = result["scope"]["kubernetes.workload.name"]
        kubernetes_workload_type = result["scope"]["kubernetes.workload.type"]

        image_pull_string = images_with_vulns_scan_results[result_id]["result"]["metadata"].get("pullString")

        #skip the result if the image pull string is blank
        if image_pull_string == "":
            LOG.warning(f"Found a blank image pull string for scan results id: {result_id}")
            continue

        image_id = images_with_vulns_scan_results[result_id]["result"]["metadata"]["imageId"]
        base_os = images_with_vulns_scan_results[result_id]["result"]["metadata"]["baseOs"]

        for package in images_with_vulns_scan_results[result_id]["result"].get("packages", {}):

            # skip packages without vulns
            if package.get("vulns") is None:
                continue

            package_type = package.get("type","")
            package_name = package.get("name","")
            package_version = package.get("version","")
            package_path = package.get("path","")
            package_suggested_fix = package.get("suggestedFix","")
            package_in_use = package.get("inUse","")

            for vuln in package.get("vulns",{}):

                vuln_name = vuln.get("name","")
                vuln_severity = vuln.get("severity", { "value": "", "sourceName" : "" })
                vuln_severity_value = vuln_severity["value"]
                vuln_severity_source = vuln_severity["sourceName"]
                vuln_cvss_score = vuln.get("cvssScore", {'value': {'version': '', 'score': '', 'vector': ''}, 'sourceName': ''})
                vuln_cvss_score_value = vuln_cvss_score.get("value",{'version': '', 'score': '', 'vector': ''})
                vuln_cvss_score_value_version = vuln_cvss_score_value["version"]
                vuln_cvss_score_value_score = vuln_cvss_score_value["score"]
                vuln_cvss_score_value_vector = vuln_cvss_score_value["vector"]
                vuln_cvss_score_source = vuln_cvss_score["sourceName"]
                vuln_disclosure_date = vuln["disclosureDate"]
                vuln_solution_date = vuln.get("solutionDate","")
                vuln_exploitable = vuln["exploitable"]
                vuln_fixed_in_version = vuln.get("fixedInVersion","")

                report_row = []
                report_row.append(vuln_name)
                report_row.append(vuln_severity_value)
                report_row.append(package_name)
                report_row.append(package_version)
                report_row.append(package_type)
                report_row.append(package_path)
                report_row.append(image_pull_string)
                report_row.append(base_os)
                report_row.append(vuln_cvss_score_value_version)
                report_row.append(vuln_cvss_score_value_score)
                report_row.append(vuln_cvss_score_value_vector)
                report_row.append('TODO') ### "Vuln link"
                report_row.append(vuln_disclosure_date)
                report_row.append(vuln_solution_date)
                report_row.append(vuln_fixed_in_version)
                report_row.append(vuln_exploitable)
                report_row.append(kubernetes_cluster_name)
                report_row.append(kubernetes_namespace_name)
                report_row.append(kubernetes_workload_name)
                report_row.append(kubernetes_workload_type)
                report_row.append(kubernetes_pod_container_name)
                report_row.append(image_id)
                report_row.append('TODO') ### "K8S POD count"
                report_row.append(package_suggested_fix)
                report_row.append(package_in_use)
                report_row.append('TODO') ### "Risk accepted")

                report_data.append(report_row)

            #end - for vuln

        #end - for package

    return report_data 

def _get_scan_results_list_with_vulnerabilties(scan_results_list):

    scan_results_list_with_vulns = []

    for result in scan_results_list:

        total_vulns = 0
        total_vulns += result["vulnTotalBySeverity"]["critical"]
        total_vulns += result["vulnTotalBySeverity"]["high"]
        total_vulns += result["vulnTotalBySeverity"]["low"]
        total_vulns += result["vulnTotalBySeverity"]["medium"]
        total_vulns += result["vulnTotalBySeverity"]["negligible"]

        if total_vulns > 0:
            scan_results_list_with_vulns.append(result)

    #end for

    return scan_results_list_with_vulns

def _get_runtime_workload_scan_results_list():

    limit=1000
    cursor=""
    json_response=None
    runtime_workload_scan_results = []

    while True:
        api_path = "secure/vulnerability/v1beta1/runtime-results"
        api_url = f"https://{secure_url_authority}/{api_path}?cursor={cursor}&filter=asset.type+%3D+'workload'&limit={limit}"
        response_data = _get_data_from_http_request(api_url)
        json_response = json.loads(response_data)

        LOG.debug(f"Found {len(json_response['data'])} entries in the json_response")

        runtime_workload_scan_results.extend(json_response["data"])

        if "next" in json_response["page"]:
            cursor = json_response["page"]["next"]
        else:
            break

    #end while

    return runtime_workload_scan_results

def _get_image_scan_results(scan_results_list_with_vulns):

    api_path = "secure/vulnerability/v1beta1/results"
    api_url = f"https://{secure_url_authority}/{api_path}"
    image_scan_results={}
    spinner = ["|", "/", "-", "\\" ]
    spinner_idx = 0
    spinner_end = 3
    num_of_results = len(scan_results_list_with_vulns)
    num_of_requests = 0
    for result in scan_results_list_with_vulns:

        #print(spinner[spinner_idx],end="\r")
        num_of_requests += 1
        print(f"{spinner[spinner_idx]} Retrieving {num_of_requests} of {num_of_results}...",end="\r")
        if spinner_idx == spinner_end:
            spinner_idx = 0
        else:
            spinner_idx += 1

        resultId = result["resultId"]
        if resultId not in image_scan_results.keys():
            response_data = _get_data_from_http_request(f"{api_url}/{resultId}")
            json_response = json.loads(response_data)
            image_scan_results[resultId]=json_response


    return image_scan_results

def _get_data_from_http_request(url):

    try:

        global num_of_429
        global num_of_504
        response_data = None

        while True:

            LOG.debug(f"Sending http request to: {url}")

            response = http_client.request(method="GET", url=url, redirect=True)
            response_data = response.data.decode()

            LOG.debug(f"Response status: {response.status}")

            if response.status == 200:
                #LOG.debug(f"Response data: {response_data}")
                break

            elif response.status in [ 429, 504 ]:

                if response.status == 429:
                    message = "API throttling"
                    num_of_429 += 1
                elif response.status == 504:
                    message = "Gateway Timeout"
                    num_of_504 += 1

                LOG.debug(f"Response data: {response_data}")
                LOG.debug(f"Sleeping 60 seconds due to {message}...")

                for interval in range(1,60):
                   print(f"Sleeping {60-interval} seconds due to {message}...", end="\r")
                   time.sleep(1)

                # Extra space to clear earlier message
                print( "Retrying request...                                    ", end="\r")

                LOG.debug(f"Retrying request...")

            else:
                raise UnexpectedHTTPResponse(
                    f"Unexpected HTTP response status: {response.status}"
                )

        return response_data

    except Exception as e:
        LOG.critical(e)
        LOG.critical(f"Error while requesting url: {url}")
        raise SystemExit(-1)

if __name__ == "__main__":
    sys.exit(main())
