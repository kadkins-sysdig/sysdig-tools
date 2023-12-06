"""
  This python script will get all vulnerability management
  accepts and allow them to be saved to a file.

  Author: Kendall Adkins
  Date December 6th, 2023
"""

import logging
import urllib3
import sys
import argparse
from datetime import datetime
import time
import json
import os

# Setup logger
LOG = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

# Setup http client
http_client = urllib3.PoolManager()

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
        "--output_file",
        required=False,
        type=str,
        action="store",
        help="File to save to.",
    )
    return parser.parse_args()

def main():

    try:

        LOG.info('Starting process to get vulnerability accepts...')

        # Parse the command line arguments
        args = _parse_args()
        secure_url_authority = args.secure_url_authority
        authentication_bearer = args.api_token
        output_file = args.output_file

        # Validate the output file
        if output_file != None and os.path.isfile(output_file):
            raise Exception(f"The output file already exists: {output_file}")

        # Get the timestamp of this run
        now = datetime.now()
        current_datetime = now.strftime("%Y-%m-%d %H:%M")

        # Add the authentication header
        http_client.headers["Authorization"] = f"Bearer {authentication_bearer}"

        # Start performance counter
        pc_start = time.perf_counter()

        # Get all accepts
        all_vuln_risk_accepts = _get_all_vuln_risk_accepts(secure_url_authority)
        LOG.info(f"Found {len(all_vuln_risk_accepts)} vulnerability risk accepts.")
        
        # Save accepts to a file
        if output_file != None and len(all_vuln_risk_accepts) > 0:
            _save_accepts(output_file, all_vuln_risk_accepts)
            LOG.info(f"Saved vulnerability accepts to: {output_file}")

        # End performance counter
        pc_end = time.perf_counter()
        LOG.info(f"Elapsed execution time: {pc_end - pc_start:0.4f} seconds")

        LOG.info('Get vulnerability accepts complete.')

    except Exception as e:
        LOG.critical(e)
        LOG.critical('Get vulnerability accepts failed.')
        raise SystemExit()

def _save_accepts(output_file, all_vuln_risk_accepts):
    
    with open(output_file, "w") as outfile:
        json.dump(all_vuln_risk_accepts, outfile, indent=2)

def _get_all_vuln_risk_accepts(secure_url_authority):

    limit=100
    cursor=""
    vuln_risk_accepts = []

    while True:

        api_path = "api/scanning/riskmanager/v2/definitions"
        api_url = f"https://{secure_url_authority}/{api_path}?cursor={cursor}&limit={limit}"
        response_data = _get_data_from_http_request(api_url)
        json_response = json.loads(response_data)

        vuln_risk_accepts.extend(json_response['data'])

        if json_response["page"]["next"] != '':
            cursor = json_response["page"]["next"]
        else:
            break

    #end while

    return vuln_risk_accepts

#def _build_unique_runtime_image_list(runtime_scan_results_list):
#
#    unique_runtime_image_list = []
#
#    for result in runtime_scan_results_list:
#        image_name = result['mainAssetName']
#        if image_name not in unique_runtime_image_list:
#            unique_runtime_image_list.append(image_name)
#
#    return unique_runtime_image_list 

#def _get_runtime_scan_results_list(secure_url_authority):
#
#    limit=1000
#    cursor=""
#    runtime_scan_results_list = []
#
#    while True:
#
#        api_path = "secure/vulnerability/v1beta1/runtime-results"
#        api_url = f"https://{secure_url_authority}/{api_path}?cursor={cursor}&limit={limit}"
#        response_data = _get_data_from_http_request(api_url)
#        json_response = json.loads(response_data)
#
#        runtime_scan_results_list.extend(json_response['data'])
#
#        if "next" in json_response["page"]:
#            cursor = json_response["page"]["next"]
#        else:
#            break
#
#    #end while
#
#    return runtime_scan_results_list

def _delete_data_from_http_request(url):

    response_data = None

    try:

        while True:
            LOG.debug(f"Sending http request to: {url}")
            response = http_client.request(method="DELETE", url=url, redirect=True)
            response_data = response.data.decode()
            LOG.debug(f"Response status: {response.status}")
            if response.status == 200:
                #LOG.debug(f"Response data: {response_data}")
                break
            elif response.status == 429:
                LOG.debug(f"Response data: {response_data}")
                LOG.info(f"Sleeping 60 seconds due to API throttling...")
                time.sleep(60)
                LOG.debug(f"Retrying request...")
            else:
                raise UnexpectedHTTPResponse(
                    f"Unexpected HTTP response status: {response.status}"
                )

    except Exception as e:
        LOG.critical(e)
        LOG.critical(f"Error while requesting url: {url}")
        raise SystemExit()

    return response_data

def _get_data_from_http_request(url):

    response_data = None

    try:

        while True:
            LOG.debug(f"Sending http request to: {url}")
            response = http_client.request(method="GET", url=url, redirect=True)
            response_data = response.data.decode()
            LOG.debug(f"Response status: {response.status}")
            if response.status == 200:
                #LOG.debug(f"Response data: {response_data}")
                break
            elif response.status == 429:
                LOG.debug(f"Response data: {response_data}")
                LOG.info(f"Sleeping 60 seconds due to API throttling...")
                time.sleep(60)
                LOG.debug(f"Retrying request...")
            else:
                raise UnexpectedHTTPResponse(
                    f"Unexpected HTTP response status: {response.status}"
                )

    except Exception as e:
        LOG.critical(e)
        LOG.critical(f"Error while requesting url: {url}")
        raise SystemExit()

    return response_data

if __name__ == "__main__":
    sys.exit(main())
