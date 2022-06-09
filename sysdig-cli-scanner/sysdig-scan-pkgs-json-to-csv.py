#
# A python script to extract the package results from the 
# JSON output of the sysdig-cli-scanner.
#
# The results are written to stdout.
#
# Tested against sysdig-cli-scanner v1.0.5
#
# Author: Kendall Adkins
# Date: June 9th, 2020
#

import sys
import os.path
import json

USAGE = "Usage: python3 "+sys.argv[0]+" [--help] | [JSON FILE]"

def validateArgs() -> None:
    args = sys.argv[1:]
    if not args:
      raise SystemExit(USAGE)

    if args[0] == "--help":
      raise SystemExit(USAGE)

    if not os.path.exists(args[0]):
      print(args[0],": No such file!")
      raise SystemExit(USAGE)

def processJsonFile() -> None:
    
    try:
      jsonFileArg = sys.argv[1:][0]
    except:
      print(args[0],": Error loading JSON file!")
      raise SystemExit(USAGE)

    with open(jsonFileArg) as json_file:
      data = json.load(json_file)

    image = data['metadata']
    imageName = image['pullString'].split(":")[0]
    imageTag = image['pullString'].split(":")[1]
    package_data = data['packages']['list']

    print("{},{},{},{},{},{},{},{},{}".format( \
      "Image Name", \
      "Image Tag", \
      "Image ID", \
      "Package Name", \
      "Package Version", \
      "Package Type", \
      "Package Path", \
      "Exploit Count", \
      "Fix Version" \
      ))

    for package in package_data:
      print("{},{},{},{},{},{},{},{},{}".format( \
        imageName, \
        imageTag, \
        image['imageID'], \
        package['name'], \
        package['version'], \
        package['type'], \
        package['packagePath'], \
        package['exploitCount'], \
        package['suggestedFix'] \
        ))

if __name__ == "__main__":
    validateArgs()
    processJsonFile()
