#
# A python script to extract the vulnerability scanning results from the 
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

USAGE = "Usage: python3 "+sys.argv[0]+" [--help] | [sysdig-cli-scanner JSON output file]"

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
    
    try:
      jsonFileArg = sys.argv[1:][0]
      with open(jsonFileArg) as json_file:
        data = json.load(json_file)

    except:
      print("Error:",sys.argv[1:][0],": Invalid JSON file!")
      raise SystemExit(USAGE)

    # Simple validation of JSON file format
    try:
        metadata = data['metadata']
        vulnerabilties = data['vulnerabilities']
        packages = data['packages']
        policies = data['policies']
        info = data['info']
    except:
      print("Error:",jsonFileArg,": JSON file is not from sysdig-cli-scanner!")
      raise SystemExit(USAGE)

    image = metadata 
    imageName = image['pullString'].split(":")[0]
    imageTag = image['pullString'].split(":")[1]
    package_data = packages['list']

    print("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format( \
      "Vulnerability ID",
      "Severity", \
      "Package Name",  \
      "Image ID", \
      "Image Name", \
      "Image Tag", \
      "Package Type",  \
      "CVSS Vector", \
      "CVSS Score", \
      "CVSS Source", \
      "CVSS Source URL", \
      "Disclosure Date", \
      "Solution Date", \
      "Fix Version", \
      "Package Version", \
      "Package Path" \
      ))

    for package in package_data:
      for vulnerability in package['vulnerabilities']:
        try:
          sourceUrl = vulnerability['cvssScore']['sourceUrl']
        except:
          sourceUrl = ""

        print("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format( \
          vulnerability['name'],
          vulnerability['severity']['label'], \
          package['name'],  \
          image['imageID'], \
          imageName, \
          imageTag, \
          package['type'],  \
          vulnerability['cvssScore']['value']['vector'], \
          vulnerability['cvssScore']['value']['score'], \
          vulnerability['cvssScore']['sourceName'], \
          sourceUrl, \
          vulnerability['disclosureDate'], \
          vulnerability['solutionDate'], \
          package['suggestedFix'], \
          package['version'], \
          package['packagePath']  \
          ))

if __name__ == "__main__":
    validateArgs()
    processJsonFile()
