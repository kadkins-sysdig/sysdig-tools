import argparse
import json
import os

# Set up argument parser
parser = argparse.ArgumentParser(description="Accept a file as an argument and validate it exists.")
parser.add_argument('logfile', type=str, help='The path to the log file')

# Parse the arguments
args = parser.parse_args()

# Validate that the file exists
if not os.path.exists(args.logfile) or not os.path.isfile(args.logfile):
    print(f"The log file '{args.logfile}' does not exist.")
    exit()

# Open and read the log file line by line
with open(args.logfile, 'r') as file:
    json_log_lines = []
    log_keys = []

    # Process each line in the file
    for line in file:
        try:
            json_log_line = json.loads(line)
            json_log_lines.append(json_log_line)
            #log_keys.update(json_log_line.keys())  # Automatically collects unique keys
            for key, value in json_log_line.items():
                if key not in log_keys:
                    log_keys.append(key)
        except json.JSONDecodeError:
            print("Error: Found invalid JSON line.")
            exit()

    # Output the csv headers
    print(",".join(log_keys))

    # Output CSV rows
    for log_line in json_log_lines:
        values = [f'"{log_line.get(column, "")}"' for column in log_keys]
        print(",".join(values))
