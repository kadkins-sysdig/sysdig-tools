"""
  This python script will split a file into multiple files 1 million lines each.

  Author: Kendall Adkins
  Date May 1st, 2023
"""

#import logging
import sys
import argparse
#import urllib3
#import json
#import urllib.parse
#from datetime import datetime
#import math
#import csv
#import platform
#import time

def _parse_args():

    args = None

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--input_file",
        required=True,
        type=str,
        action="store",
        help="input file to split",
    )
    return parser.parse_args()

def main():

    try:

        args = _parse_args()
        input_filename = args.input_file

        line_count = 0
        output_extension = 1
        with open(input_filename) as input_file:

          lines = input_file.readlines()

          for line in lines:

            if line_count == 0:
              output_filename = f"{input_filename}.{output_extension}"
              print(f"Opening file {output_filename} for writing...")
              output_file = open(output_filename, "w")

            output_file.writelines(line)
            line_count += 1

            if line_count == 1000000:
              line_count = 0
              output_extension += 1
              output_file.close()

    except Exception as e:
        print(f'Error: {e}')
        raise SystemExit()


if __name__ == "__main__":
    sys.exit(main())
