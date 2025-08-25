#!/usr/bin/env python3
import os
import time
import logging
import requests
import subprocess
import shlex

API_URL = os.environ.get("API_URL")
BEARER_TOKEN = os.environ.get("BEARER_TOKEN")
COMMAND = os.environ.get("COMMAND", "echo No results")
INTERVAL = int(os.environ.get("INTERVAL", "300"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def has_results(payload):
    """Return True if payload.page.returned > 0"""
    try:
        return payload.get("page", {}).get("returned", 0) > 0
    except Exception:
        return False

def run_command():
    logging.warning("page.returned == 0. Executing command: %s", COMMAND)
    subprocess.run(shlex.split(COMMAND))

def poll_once():
    headers = {"Authorization": f"Bearer {BEARER_TOKEN}"}
    r = requests.get(API_URL, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()

def main():
    while True:
        try:
            payload = poll_once()
            returned = payload.get("page", {}).get("returned", 0)
            logging.info("page.returned = %s", returned)

            if returned == 0:
                run_command()
                logging.info("No results left. Exiting script.")
                break  # <--- stop the script
        except Exception as e:
            logging.error("Error during poll: %s", e)
            break  # optional: exit on error too

        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
