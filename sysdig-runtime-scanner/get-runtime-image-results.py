"""
  This python script will download the the Sysdig Secure runtime scan results
  for images matching the passed image name filter.

  Author: Kendall Adkins
  Date April 6th, 2023
"""

import argparse
import logging
import sys
import urllib3
import json
import urllib.parse
from datetime import datetime

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
        "--image_name_filter",
        required=True,
        type=str,
        action="store",
        help="Image Name Filter",
    )
    return parser.parse_args()


def main():

    try:

        # Parse the command line arguments
        args = _parse_args()
        secure_url_authority = args.secure_url_authority
        authentication_bearer = args.api_token
        image_name_filter = urllib.parse.quote(args.image_name_filter)

        # Get the timestamp of this run
        now = datetime.now()
        current_datetime = now.strftime("%Y-%m-%d %H:%M")

        # Add the authentication header
        http_client.headers["Authorization"] = f"Bearer {authentication_bearer}"

        #LOG.info(f'Request for runtime scan results started.')

        # Get the runtime scan results
        #LOG.info(f"Retrieving the runtime scan results...")
        runtime_results = _get_runtime_scan_results(secure_url_authority, authentication_bearer, image_name_filter)
        #LOG.info(json.dumps(runtime_results, indent=2))

        image_results = []
        for image in runtime_results["data"]:
            image_runtime_context = image["recordDetails"]["labels"]["kubernetes.cluster.name"]
            image_runtime_context += "|"
            image_runtime_context += image["recordDetails"]["labels"]["kubernetes.namespace.name"]
            image_runtime_context += "|"
            image_runtime_context += image["recordDetails"]["labels"]["kubernetes.workload.type"]
            image_runtime_context += "|"
            image_runtime_context += image["recordDetails"]["labels"]["kubernetes.workload.name"]
            image_runtime_context += "|"
            image_runtime_context += image["recordDetails"]["mainAssetName"]
            #print(image_runtime_context)
            image_results.append((image["recordDetails"]["mainAssetName"],image_runtime_context))

        image_results.sort()
        #print(image_results)
        for image in image_results:
            print(f"{current_datetime},{image[0]},{image[1]}")

    except Exception as e:
        #LOG.critical(e)
        #LOG.error(f'Request to download runtime results failed.')
        print(e)
        print(f'Request to download runtime results failed.')
        raise SystemExit()

def _get_runtime_scan_results(secure_url_authority, authentication_bearer, image_name_filter):

    api_url = f"https://{secure_url_authority}/api/scanning/runtime/v2/workflows/results?cursor&filter=freeText%20in%20%28%22{image_name_filter}%22%29&limit=100"

    response_data = _get_data_from_http_request(api_url)
    json_response = json.loads(response_data)

    return json_response

def _get_data_from_http_request(url):

    response_data = None

    try:
        LOG.debug(f"Sending http request to: {url}")
        response = http_client.request(method="GET", url=url, redirect=True)
        response_data = response.data.decode()
        LOG.debug(f"Response data: {response_data}")
        if response.status != 200:
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
