import sys
import os
import csv
import sqlite3
from contextlib import closing

if len(sys.argv) == 1:
    print("Usage")
    sys.exit("ERROR: An input database name is required!")

dbFile = sys.argv[1]

if not os.path.isfile(dbFile):
    sys.exit(f"ERROR: The input file {dbFile} does not exist!")

try:
    print("Opening the database file...")
    with closing(sqlite3.connect(dbFile)) as conn:

        cursor = conn.cursor()

        headers = []
        headers.append("Date")
        headers.append("K8s Platform")
        headers.append("Image Type")
        headers.append("Total Images")
        headers.append("Images w/Criticals fixable for 90 days")
        headers.append("Images w/Highs fixable for 90 days")

        metrics = []
        metrics.append(headers)
    
        sqlQuery = "select date('now');"
        date = cursor.execute(sqlQuery).fetchone()

###################
# ALL
###################
        print("Gathering metrics for all platforms...")
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "all", "all", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

        #Note - we cannot do this until Kavitha sends us a list of base images
        row = [ date[0], "all", "base", "", "", "" ]
        metrics.append(row)

        sqlQuery = "select count(distinct(Image_ID)) from vulns where image like 'go0v%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where image like 'go0v%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where image like 'go0v%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "all", "infrastructure", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

        sqlQuery = "select count(distinct(Image_ID)) from vulns where image not like 'go0v%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where image not like 'go0v%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where image not like 'go0v%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "all", "application", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

###################
# EKS
###################
        print("Gathering metrics for eks platforms...")
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%eks%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%eks%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%eks%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "eks", "all", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

        #Note - we cannot do this until Kavitha sends us a list of base images
        row = [ date[0], "eks", "base", "", "", "" ]
        metrics.append(row)

        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%eks%' and image like 'go0v%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%eks%' and image like 'go0v%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%eks%' and image like 'go0v%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "eks", "infrastructure", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%eks%' and image not like 'go0v%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%eks%' and image not like 'go0v%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%eks%' and image not like 'go0v%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "eks", "application", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)
###################
# GKE
###################
        print("Gathering metrics for gke platforms...")
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%gke%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%gke%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%gke%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "gke", "all", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

        #Note - we cannot do this until Kavitha sends us a list of base images
        row = [ date[0], "gke", "base", "", "", "" ]
        metrics.append(row)

        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%gke%' and image like 'go0v%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%gke%' and image like 'go0v%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%gke%' and image like 'go0v%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "gke", "infrastructure", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%gke%' and image not like 'go0v%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%gke%' and image not like 'go0v%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name like '%gke%' and image not like 'go0v%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "gke", "application", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)
###################
# Other
###################
        print("Gathering metrics for other platforms...")
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name not like '%eks%' and k8s_cluster_name not like '%gke%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name not like '%eks%' and k8s_cluster_name not like '%gke%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name not like '%eks%' and k8s_cluster_name not like '%gke%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "other", "all", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

        #Note - we cannot do this until Kavitha sends us a list of base images
        row = [ date[0], "other", "base", "", "", "" ]
        metrics.append(row)

        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name not like '%eks%' and k8s_cluster_name not like '%gke%' and image like 'go0v%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name not like '%eks%' and k8s_cluster_name not like '%gke%' and image like 'go0v%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name not like '%eks%' and k8s_cluster_name not like '%gke%' and image like 'go0v%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "other", "infrastructure", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name not like '%eks%' and k8s_cluster_name not like '%gke%' and image not like 'go0v%' and k8s_pod_count > 0;"
        allVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name not like '%eks%' and k8s_cluster_name not like '%gke%' and image not like 'go0v%' and k8s_pod_count > 0 and severity = 'Critical' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        criticalVulns = cursor.execute(sqlQuery).fetchone()
        sqlQuery = "select count(distinct(Image_ID)) from vulns where k8s_cluster_name not like '%eks%' and k8s_cluster_name not like '%gke%' and image not like 'go0v%' and k8s_pod_count > 0 and severity = 'High' and round(julianday(date('now'))-julianday(vuln_fix_date)) > 90;"
        highVulns = cursor.execute(sqlQuery).fetchone()
        row = [ date[0], "other", "application", allVulns[0], criticalVulns[0], highVulns[0] ]
        metrics.append(row)

    print("Writing the metrics to csv file...")
    with open("vm-metrics.csv", "w") as csvFile:
        writer = csv.writer(csvFile)
        writer.writerows(metrics)

    print("Complete")

except csv.Error as e:
    if str(e) == "unknown dialect":
        print(f"CSV Error: Found ill formed CSV data in file: {inputFile}")
    else:
      print(f"CSV Exception: {e}")
