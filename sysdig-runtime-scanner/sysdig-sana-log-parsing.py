#
# A python script to parse the vulnerability scanning logs 
#
# The results are written to stdout.
#
# Author: Kendall Adkins
# Date: November 11th, 2022
#

import sys
import os.path
import json

USAGE = "Usage: python3 "+sys.argv[0]+" [--help] | [sysdig runtime scanner log]"

def validateArgs() -> None:
  args = sys.argv[1:]
  if not args:
    raise SystemExit(USAGE)

  if args[0] == "--help":
    raise SystemExit(USAGE)

  if not os.path.exists(args[0]):
    print("Error: ",args[0],": No such file!")
    raise SystemExit(USAGE)

def processJsonFile() -> None:
    
  jsonFileArg = sys.argv[1:][0]
  with open(jsonFileArg) as json_file:
    keys = []
    for line in json_file:
      data = json.loads(line)
      output = ""
      for key in data:
          keys.append(key)
    uniqueKeys = set(keys)
    headers = ""
    for key in uniqueKeys:
      headers = headers + key + ","
    print(headers)

    # build a unique list of keys from all lines
    # output the header
    # loop throughlines and output in csv of values for each key
  with open(jsonFileArg) as json_file:
    for line in json_file:
      data = json.loads(line)
      output = ""
      for key in uniqueKeys:
        try:
          output = output + data[key] + ","
        except:
          output = output + "" + ","
      print(output)

if __name__ == "__main__":
    validateArgs()
    processJsonFile()
