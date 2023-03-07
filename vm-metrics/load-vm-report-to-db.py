import sys
import os
import csv
import sqlite3
from contextlib import closing

if len(sys.argv) == 1:
    print("Usage")
    sys.exit("ERROR: An input file name argument is required!")

inputFile = sys.argv[1]

if not os.path.isfile(inputFile):
    sys.exit(f"ERROR: The input file {inputFile} does not exist!")

try:
    count = 0
    print("Opening the CSV file...")
    with open(inputFile, 'r') as csvFile:
        csvReader = csv.reader(csvFile)
        if os.path.isfile("vulns.db"):
            sys.exit(f"ERROR: The database file vulns.db already exists!")
            #os.remove("vulns.db")

        print("Opening the database file...")
        with closing(sqlite3.connect("vulns.db")) as conn:

            cursor = conn.cursor()

            createTableSQL = "CREATE TABLE vulns (Vulnerability_ID TEXT, Severity TEXT, Package_name TEXT, Package_version TEXT, Package_type TEXT, Package_path TEXT, Image TEXT, OS_Name TEXT, CVSS_version TEXT, CVSS_score TEXT, CVSS_vector TEXT, Vuln_link TEXT, Vuln_Publish_date TEXT, Vuln_Fix_date TEXT, Fix_version TEXT, Public_Exploit TEXT, K8S_cluster_name TEXT, K8S_namespace_name TEXT, K8S_workload_type TEXT, K8S_workload_name TEXT, K8S_container_name TEXT, Image_ID TEXT, K8S_POD_count TEXT, Package_suggested_fix TEXT, In_use TEXT, Risk_accepted TEXT)"

            print("Creating the database table...")
            cursor.execute(createTableSQL)

            insertRecordsSQL = "INSERT INTO vulns (Vulnerability_ID, Severity, Package_name, Package_version, Package_type, Package_path, Image, OS_Name, CVSS_version, CVSS_score, CVSS_vector, Vuln_link, Vuln_Publish_date, Vuln_Fix_date, Fix_version, Public_Exploit, K8S_cluster_name, K8S_namespace_name, K8S_workload_type, K8S_workload_name, K8S_container_name, Image_ID, K8S_POD_count, Package_suggested_fix, In_use, Risk_accepted) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

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
