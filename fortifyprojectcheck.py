import requests
import json
import os

# project lists

fortifyserver="https://fortify.com/ssc"
allProject = fortifyserver + "/api/v1/projects"
baseUrl = fortifyserver + "/api/v1/projectVersions/{}/issues"
versionUrl = fortifyserver + "/api/v1/projects/{}/versions"
#pattern to filter projects
project_name_pattern="xxx"
project_version="1.0"

# authorization token is generated in fortify server, base64 format, below is a sample value
authheaders = {
    "Authorization": "FortifyToken c2FtcGxldG9rZW4=",
    "Accept": "application/json"
}

try:
    os.remove("fortify_result_ok.txt")
    os.remove("fortify_result_ko.txt")
except:
    print("file not exists")
finally:
    print("continue processing...")

f = open("fortify_result_ok.txt", "w")
f_ko = open("fortify_result_ko.txt", "w")
# could add cert to verify server cert
# request all projects
data = requests.request('get', allProject, headers=authheaders, verify=False)
jsondata = json.loads(data.text)
projects_to_check = jsondata['data']
result = ''
versionId = 0
for project in projects_to_check:
    projectId = project["id"]
    projectName = project["name"]
    if not projectName.lower().startswith(project_name_pattern):
        continue
    data = requests.request('get', versionUrl.format(projectId), headers=authheaders, verify=False)
    jsondata = json.loads(data.text)
    versionDatas = jsondata['data']
    for versionData in versionDatas:
        if versionData['name'] == project_version:
            versionId = versionData['id']
    if versionId == 0:
        print('version not exist for project' + versionDatas)
    data = requests.request('get', baseUrl.format(versionId), headers=authheaders, verify=False)
    jsondata = json.loads(data.text)
    issues = jsondata['data']
    print("project name: " + projectName)
    print("issues numbers: " + str(len(issues)))
    newIssues = []
    donotfix_critical = 0
    donotfix_high = 0
    suspicious_critical = 0
    suspicious_high = 0
    notanissue_critical = 0
    notanissue_high = 0
    nonecomment_critical = 0
    nonecomment_high = 0


#retrieve only critical and high vulnerabilities
    for vuln in issues:
        if (vuln['primaryTag'] == None ) and (vuln['friority'] == "Critical" or vuln['friority'] == "High"):
            issue = {'friority': vuln['friority'], 'fullFileName': vuln['fullFileName'],
                     'issueStatus': vuln['issueStatus'], '_href': vuln['_href']}
            newIssues.append(issue)
            continue;

        if vuln['friority'] == "Critical":
            if vuln['primaryTag'].lower() == 'not an issue':
                notanissue_critical = notanissue_critical + 1
            elif vuln['primaryTag'].lower() == 'suspicious':
                suspicious_critical = suspicious_critical + 1
            elif vuln['primaryTag'].lower() == 'do not fix':
                donotfix_critical = donotfix_critical + 1
        if vuln['friority'] == "High":
            if vuln['primaryTag'].lower() == 'not an issue':
                notanissue_high = notanissue_high + 1
            elif vuln['primaryTag'].lower() == 'suspicious':
                suspicious_high = suspicious_high + 1
            elif vuln['primaryTag'].lower() == 'do not fix':
                donotfix_high = donotfix_high + 1
    result_ko = ''
    if (len(newIssues)) > 0:
        result_ko = projectName + ": \n"
        result_ko = result_ko + '-----to be reviewed----- \n'
        for i in newIssues:
            result_ko = result_ko + i['fullFileName'] + '\n'
            result_ko = result_ko + i['_href'] + '\n'

        result_ko = result_ko + '-----to be reviewed----- \n '

    result_ok = projectName + ": \n"
    result_ok = result_ok + "issues numbers: " + str(len(issues)) + '\n'
    result_ok = result_ok + "do not fix: " + str(donotfix_critical) + "/" + str(donotfix_high) + "\n"
    result_ok = result_ok + "suspicious: " + str(suspicious_critical) + "/" + str(suspicious_high) + "\n"
    result_ok = result_ok + "Not an Issue: " + str(notanissue_critical) + "/" + str(notanissue_high) + "\n"
    f.write(result_ok)
    f.write('\n')
    f_ko.write(result_ko)
f.close()
f_ko.close()
