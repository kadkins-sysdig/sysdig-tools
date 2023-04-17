import http.client
import json
import csv

# the api endpoint
apiEndPoint = "us2.app.sysdig.com"

# The customer api keys to collect from
customerApiKey = "xxxxxxxxxxxxx"

# the result filters to use
filters = ["Up+to+Date", "Almost+Out+of+Date", "Out+of+Date"]

# startup an http client
conn = http.client.HTTPSConnection(apiEndPoint)

# initialize the csv output file
csvFileName = 'agent-data.csv'
csvFile = open('agent-data.csv', 'w', newline='')
csv_writer = csv.writer(csvFile)
csv_headers_written = False

# build the auth header
authHeader = {"Authorization": f"Bearer {customerApiKey}"}

# retrieve results for each filter
for filter in filters:

    print(
        f"Getting results for customer with status of {filter}...")

    # execute the query
    apiUrl = f"/api/cloud/v2/dataSources/agents?status={filter}"
    conn.request("GET", url=apiUrl, headers=authHeader)
    response = conn.getresponse()
    print(f"http status code := {response.status}")

    # load the results
    print("Loading json results...")
    jsonData = json.loads(response.read().decode("utf-8"))
    # DEBUG print(json.dumps(jsonData, indent=2))
    # DEBUG raise SystemExit()

    # convert the results to json and append the customer id column
    print("Writing to CSV file...")
    if 'details' in jsonData.keys():
        for jsonObject in jsonData['details']:
            if not csv_headers_written:
                headers = []
                for header in jsonObject.keys():
                    headers.append(header)
                    if header == "agentLastSeen":
                        headers.append("clusterName")
                csv_headers_written = True
                csv_writer.writerow(headers)
            row = list(jsonObject.values())
            if len(row) < 8:
                row.insert(4, "--")
            csv_writer.writerow(row)

# close the csv output file
csvFile.close()

print(f"Complete - results written to {csvFileName}")
