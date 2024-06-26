"""
  This python script will list and/or remove orphaned vulnerability management
  accepts. An accept for an image that is no longer running will be considered
  an orphan.

  Author: Kendall Adkins
  Date July 11th, 2023

  Currently Handles:
     accept.context_type.context.contextType == "imageName" (Image CVE)
     accept.entity_type == "imageName" (Global Image)

  Currently Does NOT handle:
     accept.context.contextType: imageAssetToken
     accept.context.contextType: imagePrefix
     accept.context.contextType: imageSuffix
     accept.context.contextType: packageName
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
        help="File to save orphans to.",
    )
    parser.add_argument(
        "--delete",
        required=False,
        action="store_true",
        help="Orphans will be deleted",
    )
    return parser.parse_args()

def main():

    try:

        LOG.info('Starting process to cleanup orphaned accepts...')

        # Parse the command line arguments
        args = _parse_args()
        secure_url_authority = args.secure_url_authority
        authentication_bearer = args.api_token
        output_file = args.output_file
        delete_orphans = args.delete

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

        # Get the runtime scan results
        LOG.info(f"Retrieving the runtime scan results...")
        runtime_scan_results_list = _get_runtime_scan_results_list(secure_url_authority)
        
        # Build a unique image list from the runtime results list
        unique_runtime_image_list = _build_unique_runtime_image_list(runtime_scan_results_list)
        LOG.info(f"Found {len(unique_runtime_image_list)} unique images in {len(runtime_scan_results_list)} scan results.")

        # Get all accepts
        all_vuln_risk_accepts = _get_all_vuln_risk_accepts(secure_url_authority)
        LOG.info(f"Found {len(all_vuln_risk_accepts)} vulnerability risk accepts.")
        
        # Get the image accepts
        image_vuln_risk_accept_ids = []
        if len(all_vuln_risk_accepts) > 0:
            image_vuln_risk_accept_ids = _get_image_vuln_risk_accepts(all_vuln_risk_accepts)
            LOG.info(f"Found {len(image_vuln_risk_accept_ids)} images with vulnerability risk accepts.")

        # Identify orphaned accepts
        image_orphaned_risk_accepts_ids = []
        if len(image_vuln_risk_accept_ids) > 0:
            image_orphaned_risk_accepts_ids = _find_orphaned_risk_accepts(unique_runtime_image_list, image_vuln_risk_accept_ids)
            LOG.info(f"Found {len(image_orphaned_risk_accepts_ids)} orphaned images with vulnerability risk accepts.")
            orphaned_risk_accepts_count = _count_orphaned_risk_accepts(image_orphaned_risk_accepts_ids)
            LOG.info(f"Found {orphaned_risk_accepts_count} orphaned vulnerability risk accepts.")

        # Save orphaned accepts to a file
        if output_file != None and len(image_orphaned_risk_accepts_ids) > 0:
            _save_orphaned_accepts(output_file, all_vuln_risk_accepts, image_orphaned_risk_accepts_ids)
            LOG.info(f"Saved orphaned risk accepts to: {output_file}")
        elif output_file != None and len(image_orphaned_risk_accepts_ids) == 0:
            LOG.info(f"There is nothing to save to: {output_file}")

        # Delete orphaned accepts
        if not delete_orphans and len(image_orphaned_risk_accepts_ids) > 0:
            LOG.info(f"Skipping delete of orphaned vulnerability risk accepts.")
        elif delete_orphans and len(image_orphaned_risk_accepts_ids) > 0:
            LOG.info(f"Deleting orphaned image vulnerability risk accepts.")
            _delete_orphaned_risk_accepts(secure_url_authority, image_orphaned_risk_accepts_ids)
            LOG.info(f"Deleted orphaned image vulnerability risk accepts.")
        else:
            LOG.info(f"No orphaned image vulnerability risk accepts found.")

        # End performance counter
        pc_end = time.perf_counter()
        LOG.info(f"Elapsed execution time: {pc_end - pc_start:0.4f} seconds")

        LOG.info('Request to cleanup orphaned accepts complete.')

    except Exception as e:
        LOG.critical(e)
        LOG.critical('Request to cleanup orphaned accepts failed.')
        raise SystemExit()

def _save_orphaned_accepts(output_file, all_vuln_risk_accepts, image_orphaned_risk_accepts_ids):
    
    orphaned_accept_ids = []
    accepts_to_save = []
   
    for image_name in image_orphaned_risk_accepts_ids.keys():
        for accept_def_id in image_orphaned_risk_accepts_ids[image_name]:
            orphaned_accept_ids.append(accept_def_id)

    for accept in all_vuln_risk_accepts:
        acceptId = accept['riskAcceptanceDefinitionID']
        if acceptId in orphaned_accept_ids:
            accepts_to_save.append(accept)

    with open(output_file, "w") as outfile:
        json.dump(accepts_to_save, outfile, indent=2)

def _count_orphaned_risk_accepts(image_orphaned_risk_accepts_ids):

    count = 0

    for image_name in image_orphaned_risk_accepts_ids.keys():
        for accept_def_id in image_orphaned_risk_accepts_ids[image_name]:
            count += 1

    return count

def _delete_orphaned_risk_accepts(secure_url_authority, image_orphaned_risk_accepts_ids):

    api_path = "api/scanning/riskmanager/v2/definitions"
    deleted_ids = []

    for image_name in image_orphaned_risk_accepts_ids.keys():
        for accept_def_id in image_orphaned_risk_accepts_ids[image_name]:
            if accept_def_id not in deleted_ids:
                api_url = f"https://{secure_url_authority}/{api_path}/{accept_def_id}"
                _delete_data_from_http_request(api_url)
                deleted_ids.append(accept_def_id)
            else:
                LOG.debug(f"Found accept already deleted: {accept_def_id}")

    return

def _find_orphaned_risk_accepts(unique_runtime_image_list, image_vuln_risk_accept_ids):

    image_orphaned_risk_accepts_ids = []
    image_vuln_risk_accept_ids_copy = image_vuln_risk_accept_ids.copy()

    images_still_running = [value for value in image_vuln_risk_accept_ids.keys() if value in unique_runtime_image_list]

    for image in images_still_running:
        del image_vuln_risk_accept_ids_copy[image]

    image_orphaned_risk_accepts_ids = image_vuln_risk_accept_ids_copy

    return image_orphaned_risk_accepts_ids

def _get_image_vuln_risk_accepts(all_vuln_risk_accepts):

    image_vuln_risk_accept_ids = {}

    for accept in all_vuln_risk_accepts:
        entity_type = accept['entityType']

        # Image CVE Accepts
        if entity_type == "vulnerability" and len(accept['context']) > 0:
            
            context_type = accept['context'][0]['contextType']

            if context_type == "imageName":
                accept_def_id = accept['riskAcceptanceDefinitionID']
                image_name = accept['context'][0]['contextValue']

                if image_name not in image_vuln_risk_accept_ids.keys():
                    image_vuln_risk_accept_ids[image_name] = []

                image_vuln_risk_accept_ids[image_name].append(accept_def_id)

        # Global Image Accepts
        elif entity_type == "imageName":

            accept_def_id = accept['riskAcceptanceDefinitionID']
            image_name = accept['entityValue']

            if image_name not in image_vuln_risk_accept_ids.keys():
                image_vuln_risk_accept_ids[image_name] = []

            image_vuln_risk_accept_ids[image_name].append(accept_def_id)

    #end for

    return image_vuln_risk_accept_ids


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

def _build_unique_runtime_image_list(runtime_scan_results_list):

    unique_runtime_image_list = []

    for result in runtime_scan_results_list:
        image_name = result['mainAssetName']
        if image_name not in unique_runtime_image_list:
            unique_runtime_image_list.append(image_name)

    return unique_runtime_image_list 

def _get_runtime_scan_results_list(secure_url_authority):

    limit=1000
    cursor=""
    runtime_scan_results_list = []

    while True:

        api_path = "secure/vulnerability/v1beta1/runtime-results"
        api_url = f"https://{secure_url_authority}/{api_path}?cursor={cursor}&limit={limit}"
        response_data = _get_data_from_http_request(api_url)
        json_response = json.loads(response_data)

        runtime_scan_results_list.extend(json_response['data'])

        if "next" in json_response["page"]:
            cursor = json_response["page"]["next"]
        else:
            break

    #end while

    return runtime_scan_results_list

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
