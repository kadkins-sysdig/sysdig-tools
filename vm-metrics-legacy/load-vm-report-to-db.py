import sys
import os
import csv
import sqlite3
from contextlib import closing


if len(sys.argv) != 3:
    print("Usage: TODO inputfile output-db.name")
    sys.exit("ERROR: An input file name argument is required!")

inputFile = sys.argv[1]
outputDbName = sys.argv[2]

if not os.path.isfile(inputFile):
    sys.exit(f"ERROR: The input file {inputFile} does not exist!")

if os.path.isfile(outputDbName):
    sys.exit(f"ERROR: The output database file {outputDbName} already exists!")

try:
    count = 0
    print("Opening the CSV file...")
    with open(inputFile, 'r') as csvFile:
        csvReader = csv.reader(csvFile)
        if os.path.isfile(outputDbName):
            sys.exit(f"ERROR: The database file vulns.db already exists!")
            # os.remove(outputDbName)

        print("Opening the database file...")
        with closing(sqlite3.connect(outputDbName)) as conn:

            cursor = conn.cursor()

            createTableSQL = "CREATE TABLE vulns (Vulnerability_ID TEXT, Severity TEXT, Package_name TEXT, Image_ID TEXT, Image_name TEXT, Image_tag TEXT, Vulnerability_type TEXT, CVSS_v2_vector TEXT, CVSS_v2_base_score TEXT, CVSS_v3_vector TEXT, CVSS_v3_base_score TEXT, Vuln_link TEXT, Disclosure_date TEXT, Solution_date TEXT, Fix_version TEXT, Vuln_exception TEXT, Package_version TEXT, Package_path TEXT, Image_added TEXT, Pod TEXT, Namespace TEXT, Container_Name TEXT, Container_ID TEXT, Cluster_Name TEXT, Deployment TEXT, Hostname TEXT)"

            print("Creating the database table...")
            cursor.execute(createTableSQL)

            insertRecordsSQL = "INSERT INTO vulns (Vulnerability_ID, Severity, Package_name, Image_ID, Image_name, Image_tag, Vulnerability_type, CVSS_v2_vector, CVSS_v2_base_score, CVSS_v3_vector, CVSS_v3_base_score, Vuln_link, Disclosure_date, Solution_date, Fix_version, Vuln_exception, Package_version, Package_path, Image_added, Pod, Namespace, Container_Name, Container_ID, Cluster_Name, Deployment, Hostname) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            print("Loading the data...")
            cursor.executemany(insertRecordsSQL, csvReader)

            print("Committing the data...")
            conn.commit()

            print("Complete!")

except csv.Error as e:
    if str(e) == "unknown dialect":
        print(f"CSV Error: Found ill formed CSV data in file: {inputFile}")
    else:
      print(f"CSV Exception: {e}")
