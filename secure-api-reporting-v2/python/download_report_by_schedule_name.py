"""
  This python script will download the a Sysdig Secure runtime vulnerability report 
  by schedule name.

  Author: Kendall Adkins
  Date November 21st, 2022
"""

import argparse
import logging
import sys
from typing import overload
import urllib3
import gzip
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
        "--schedule_name",
        required=True,
        type=str,
        action="store",
        help="Sysdig Secure Runtime Report Schedule Name",
    )
    parser.add_argument(
        "--decompress",
        required=False,
        action="store_true",
        help="Will decompress the downloaded report file",
    )
    parser.add_argument(
        "--debug",
        required=False,
        action="store_true",
        help="""will enable debug level logging""",
    )
    return parser.parse_args()


def main():

    try:

        # Parse the command line arguments
        args = _parse_args()

        if args.debug:
            LOG.setLevel(logging.DEBUG)
            logging.getLogger("urllib3").setLevel(logging.DEBUG)

        secure_url_authority = args.secure_url_authority
        authentication_bearer = args.api_token
        schedule_name = args.schedule_name

        # Add the authentication header
        http_client.headers["Authorization"] = f"Bearer {authentication_bearer}"

        LOG.info(f'Request to download report from schedule "{schedule_name}" started.')

        # Get the user info associated with the api key or exit on invalid api key
        LOG.info(f"Retrieving api key user info...")
        if len(authentication_bearer) == 36:
            userinfo = _get_apikey_userinfo(secure_url_authority, authentication_bearer)
        elif len(authentication_bearer) == 41:
            userinfo = {"username": "Service Account", "teamname": "Unknown"}
        else:
            raise Exception(
                "Invalid API Key!"
            )

        # Retrieve the report schedules and exit if no schedules found
        LOG.info(
            'Retrieving report schedules for username "{}" in team "{}"...'.format(
                userinfo["username"], userinfo["teamname"]
            )
        )
        report_schedules = _get_report_schedules(
            secure_url_authority, authentication_bearer
        )
        if len(report_schedules) == 0:
            raise Exception(
                'No report schedules found for team "{}"'.format(userinfo["teamname"])
            )

        # Search for the report schedule name and exit if duplicates exist or it is not found
        LOG.info(f'Searching for schedule name "{schedule_name}"...')
        report_schedule_id = _get_report_schedule_id(report_schedules, schedule_name)
        LOG.info(f'Found schedule "{schedule_name}" with id of "{report_schedule_id}".')

        # Retrieve the report schedule status and exit if it has not been run
        report_schedule_status = _get_report_schedule_status(
            secure_url_authority, authentication_bearer, report_schedule_id
        )
        if "currentReport" in report_schedule_status.keys():
            LOG.warning(
                "A new report is currently running or scheduled to run. Ignoring and retrieving the last completed report."
            )
        if "lastCompletedReport" in report_schedule_status.keys():
            LOG.info(
                "Preparing to download report generated at {}".format(
                    report_schedule_status["lastCompletedReport"]["scheduledAt"]
                )
            )
            report_id = report_schedule_status["lastCompletedReport"]["reportId"]
        else:
            raise Exception(
                f'The report schedule "{schedule_name}" has never been run.'
            )

        # Build the report file name
        compressed_report_filename = _build_report_filename(
            schedule_name, report_schedule_status
        )

        if os.path.exists(compressed_report_filename):
            LOG.warning(
                f"Report file {compressed_report_filename} already exists and will be overwritten!"
            )

        # Download the report
        LOG.info(f"Downloading report to file {compressed_report_filename}")
        _download_report(
            secure_url_authority,
            authentication_bearer,
            report_schedule_id,
            report_id,
            compressed_report_filename,
        )

        # Decompress the report file
        if args.decompress:
            decompressed_report_filename = compressed_report_filename.rstrip(".gz")
            if os.path.exists(decompressed_report_filename):
                LOG.warning(
                    f'Decompressed report file "{decompressed_report_filename}" already exists and will be overwritten!'
                )
            decompress_file(
                input_filename=compressed_report_filename,
                output_filename=decompressed_report_filename,
            )
            os.remove(compressed_report_filename)
            LOG.info(
                f'Decompressed the report file to "{decompressed_report_filename}"'
            )

        LOG.info(
            f'Request to download report from schedule "{schedule_name}" complete.'
        )

    except Exception as e:
        LOG.critical(e)
        LOG.error(f'Request to download report from schedule "{schedule_name}" failed.')
        raise SystemExit()


def _get_apikey_userinfo(secure_url_authority, authentication_bearer):

    api_url = f"https://{secure_url_authority}/api/users/me"

    response_data = _get_data_from_http_request(api_url)

    json_response = json.loads(response_data)

    userinfo = {}
    userinfo["username"] = json_response["user"]["username"]
    currentTeam = json_response["user"]["currentTeam"]
    for team in json_response["user"]["teamRoles"]:
        if team["teamId"] == currentTeam:
            userinfo["teamname"] = team["teamName"]
            break

    return userinfo


def _get_report_schedules(secure_url_authority, authentication_bearer):
    api_url = f"https://{secure_url_authority}/api/scanning/reporting/v2/schedules"
    response_data = _get_data_from_http_request(api_url)
    return json.loads(response_data)


def _get_report_schedule_id(report_schedules, schedule_name):
    schedule_ids = []
    for schedule in report_schedules:
        if schedule_name == schedule["name"]:
            schedule_ids.append(schedule["id"])
    if (len(schedule_ids)) == 0:
        raise Exception(f'Report schedule "{schedule_name}" not found!')
    elif (len(schedule_ids)) > 1:
        raise Exception(
            f'More than one schedule found with the name "{schedule_name}"!'
        )

    return schedule_ids[0]


def _get_report_schedule_status(
    secure_url_authority, authentication_bearer, report_schedule_id
):
    api_url = f"https://{secure_url_authority}/api/scanning/reporting/v2/schedules/{report_schedule_id}/status"
    content_type = "application/json;charset=UTF-8"
    response_data = _get_data_from_http_request(api_url)
    return json.loads(response_data)


def _build_report_filename(schedule_name, report_schedule_status):
    filename = schedule_name.replace(" ", "-")
    normal_string = "".join(ch for ch in filename if ch.isalnum())
    suffix = (
        report_schedule_status["lastCompletedReport"]["scheduledAt"]
        .replace("Z", "")
        .replace("-", "")
        .replace("T", "-")
        .replace(":", "")
    )
    extension = report_schedule_status["lastCompletedReport"]["reportFormat"]

    return "{}-{}.{}.gz".format(filename, suffix, extension).lower()


def _download_report(
    secure_url_authority,
    authentication_bearer,
    schedule_id,
    report_id,
    download_filename,
):

    try:
        api_url = f"https://{secure_url_authority}/api/scanning/reporting/v2/schedules/{schedule_id}/reports/{report_id}/download"
        _save_data_from_http_request(url=api_url, download_filename=download_filename)

    except Exception as e:
        LOG.error(f"{e}")
    return


def decompress_file(input_filename, output_filename):

    with open(input_filename, "rb") as input_file, open(
        output_filename, "w", encoding="utf8"
    ) as output_file:
        decom_str = gzip.decompress(input_file.read()).decode("utf-8")
        output_file.write(decom_str)
    return


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


def _save_data_from_http_request(url, download_filename):

    with http_client.request(
        method="GET", url=url, redirect=True, preload_content=False
    ) as response:

        with open(download_filename, "wb") as outputFile:
            for chunk in response.stream(512):
                outputFile.write(chunk)


if __name__ == "__main__":
    sys.exit(main())
