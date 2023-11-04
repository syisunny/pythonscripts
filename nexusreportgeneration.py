import os

import requests
import json
import pandas as pd

from requests import RequestException
from requests.auth import HTTPBasicAuth

# project lists

#to be changed
projectName = ['project_1', 'project_2', 'project_3']
serverName = "https://nexusiqservername.nexus.com"
auth = HTTPBasicAuth('dXNlcgo=', 'cHdkCg==')
final_file="nexusiqreport.xlsx"


sampleProject = serverName + "/api/v2/applications?publicId={}"
reportApp = serverName + "/api/v2/reports/applications/{}/history"
reportData = serverName + "{}"

debug = False
write_to_file = True


def combine_all_csv():
    folder_path = os.getcwd()
    all_files = os.listdir(folder_path)
    csv_files = [f for f in all_files if f.endswith('.csv')]
    writer = pd.ExcelWriter(final_file)
    i = 0
    for csv in csv_files:
        file_path = os.path.join(folder_path, csv)
        try:
            # Try reading the file using default UTF-8 encoding
            df = pd.read_csv(file_path, sep=";", header=None)
            df.to_excel(writer, csv.split(".")[0])
        except UnicodeDecodeError:
            try:
                # If UTF-8 fails, try reading the file using UTF-16 encoding with tab separator
                df = pd.read_csv(file_path, sep='\t', encoding='utf-16')
                df.to_excel(writer, csv.split(".")[0])
            except Exception as e:
                print(f"Could not read file {csv} because of error: {e}")
        except Exception as e:
            print(f"Could not read file {csv} because of error: {e}")
    writer.close()


def send_http_request(url):
    try:
        data = requests.request('get', url, auth=auth, verify=False)
        if data.status_code != 200:
            raise ConnectionError("Failed to retrieve data from " + url + "; Reason: " + data.text)
        json_data = json.loads(data.text)
    except RequestException as e:
        print("URL: " + url + "\n")
        print("Error Message: " + e.response.text)
        raise ConnectionError("Failed to retrieve data from " + url)
    return json_data


def get_project_data(projectname):

    try:
        json_data = send_http_request(sampleProject.format(projectname))
    except ConnectionError as e:
        raise e

    project_data = json_data['applications']
    id = project_data[0]['id']

    if debug:
        print(project_data[0]['name'])
    # print(id)
    json_data = send_http_request(reportApp.format(id))
    report_info = json_data['reports'][0]

    if debug:
        print('evaluationDate: ' + report_info['evaluationDate'])
    report_raw_info = report_info['reportDataUrl']
    # print(report_info)

    json_data = send_http_request(reportData.format(report_raw_info))

    # print(jsondata)
    components = json_data['components']
    f = open(projectname + ".csv", "w")
    if write_to_file:
        f_json = open(projectname + ".json", "w")
    vuln_list = []
    for i in components:
        security_data = i['securityData']
        comp_name = ""
        comp_name = i['displayName']
        if security_data is not None:
            security_issues = security_data['securityIssues']
            if security_issues is not None and len(security_issues) > 0:
                reference = []
                for issue in security_issues:
                    if issue['severity'] > 7:
                        reference.append(issue['reference'] + ";" + str(issue['severity']))

                if len(reference) > 0:
                    if debug:
                        print('module name: \n' + i['displayName'])
                        print(reference)
                    vuln_module = {comp_name: reference}
                    vuln_list.append(vuln_module)

                    for ref in reference:
                        f.write(i['displayName'] + ";" + ref)
                        f.write('\n')
    if write_to_file:
        if len(vuln_list) > 0:
            f_json.write(json.dumps(vuln_list))
    f.close()
    if write_to_file:
        f_json.close()


for project in projectName:
    print('------------start project report generation--------------')
    print('prj to analyze: ' + project)
    try:
        get_project_data(project)
    except ConnectionError as e:
        print('prj with error: ' + project)
        print('Error: ' + str(e))
        continue
combine_all_csv()
print('------------end project report generation--------------')