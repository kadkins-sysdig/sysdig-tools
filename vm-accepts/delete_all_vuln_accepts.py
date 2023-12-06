"""
  This python script will delete all vulnerability risk accepts

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
    return parser.parse_args()

def main():

    try:

        LOG.info('Starting process to delete all vulnerability accepts...')

        # Parse the command line arguments
        args = _parse_args()
        secure_url_authority = args.secure_url_authority
        authentication_bearer = args.api_token

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
        
        # Delete accepts
        vuln_risk_accept_ids = _get_vuln_risk_accept_ids(all_vuln_risk_accepts)
        _delete_vuln_risk_accepts(secure_url_authority, vuln_risk_accept_ids)
        LOG.info(f"Deleted {len(all_vuln_risk_accepts)} vulnerability risk accepts.")

        # End performance counter
        pc_end = time.perf_counter()
        LOG.info(f"Elapsed execution time: {pc_end - pc_start:0.4f} seconds")

        LOG.info('Request to delete vulnerability accepts complete.')

    except Exception as e:
        LOG.critical(e)
        LOG.critical('Request to delete vulnerability accepts failed.')
        raise SystemExit()

def _delete_vuln_risk_accepts(secure_url_authority, vuln_risk_accept_ids):

    api_path = "api/scanning/riskmanager/v2/definitions"

    for accept_def_id in vuln_risk_accept_ids:
        api_url = f"https://{secure_url_authority}/{api_path}/{accept_def_id}"
        LOG.info(f"Calling {api_url}")
        _delete_data_from_http_request(api_url)

    return

def _get_vuln_risk_accept_ids(all_vuln_risk_accepts):

    vuln_risk_accept_ids = []

    for accept in all_vuln_risk_accepts:

        entity_type = accept['entityType']

        if entity_type == "vulnerability":
            accept_def_id = accept['riskAcceptanceDefinitionID']
            vuln_risk_accept_ids.append(accept_def_id)

    #end for

    return vuln_risk_accept_ids

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
