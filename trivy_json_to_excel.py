import json
import os
import pandas as pd



def find_all_report():
    path = os.getcwd() + '\\jsonreports\\'
    return os.listdir(path)


def get_project_data(projectnames):
    data_to_write = []
    for projectname in projectnames:
        print('prj to analyze: ' + projectname)
        path = os.getcwd() + '\\jsonreports\\'
        service_name = projectname.split('.')[0]
        filepath = path + projectname
        with open(filepath, encoding='utf-8') as file:
            data = json.loads(file.read())
            results = data.get("Results")
            for result in results:
                if result.get("Vulnerabilities") is not None:
                    vulnerabilities = result.get("Vulnerabilities")
                    vulnerability_type = ""
                    if result.get("Type") is not None:
                        vulnerability_type = result.get('Type')
                    for vulnerability in vulnerabilities:
                        cve_id = vulnerability.get("VulnerabilityID")
                        pkgName = vulnerability.get('PkgName')
                        version = vulnerability.get('InstalledVersion')
                        severity = vulnerability.get('Severity')
                        pkg_path = vulnerability.get('PkgPath')
                        ghsa_score = None
                        nvd_score = None
                        if vulnerability.get('CVSS') is not None:
                            cvss = vulnerability.get('CVSS')
                            if cvss.get('ghsa') is not None:
                                ghsa = cvss.get('ghsa')
                                ghsa_score = ghsa.get('V3Score')
                            if cvss.get('nvd') is not None:
                                nvd = cvss.get('nvd')
                                nvd_score = nvd.get('V3Score')
                        record = {'Service': service_name, 'Type': vulnerability_type, 'CVEID': cve_id, 'pkgName': pkgName, 'version': version, 'severity': severity, 'ghsa score': ghsa_score, 'nvd score': nvd_score, 'packagepath': pkg_path}
                        data_to_write.append(record)
    df = pd.DataFrame(data_to_write)
    df.to_excel(writer)


projectName = find_all_report()
writer = pd.ExcelWriter('trivyreports.xlsx')
get_project_data(projectName)
writer.close()