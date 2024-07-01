import os
import json
import pprint
import re
import argparse
from statistics import mean
from collections import Counter, defaultdict

import numpy as np
import matplotlib.pyplot as plt


# Tools
sca_tools = ['Grype.txt', 'Snyk.txt', 'Trivy.txt']

# RICs
rics = ['ONOS', 'OSC']

repoWithError = []

# Packages to exclude in the RIC repos
test_package = re.compile(r'test/')
benchmark_package = re.compile(r'benchmark')
examples_package = re.compile(r'examples/')
testapplication_package = re.compile(r'testapplication/')


# First we normalize the results from each tool
def format_sca_tool_data(repository, tool):
    if tool == "Grype.txt":
        return formatGrype(repository)
    elif tool == "Snyk.txt":
        return formatSnyk(repository)
    elif tool == "Trivy.txt":
        return formatTrivy(repository)

# This gets all the vulnerabilities in a normalized way.
# (In a list which includes all the vulnerabilities, which are not contained in a test package)
def formatGrype(repository):
    GrypeRepo = json.loads(repository)
    vulnArray = []
    for vuln in GrypeRepo["matches"]:
        path = vuln.get("artifact").get("locations")[0].get("path")
        if test_package.search(path) is not None:
            continue
        elif benchmark_package.search(path) is not None:
            continue
        elif examples_package.search(path) is not None:
            continue
        elif testapplication_package.search(path) is not None:
            continue
        else:
            vulnArray.append(vuln)
    return vulnArray

def formatSnyk(repository):
    content = json.loads(repository)
    vulnArray = []
    if "error" not in content:
        for target in content:
            if not isinstance(target, str):
                vulnList = target.get('vulnerabilities')
                path = target.get('displayTargetFile')
                if test_package.search(path) is not None:
                    print("Snyk: Skipping:" + path)
                    continue
                elif benchmark_package.search(path) is not None:
                    print("Snyk: Skipping:" + path)
                    continue
                elif examples_package.search(path) is not None:
                    print("Snyk: Skipping:" + path)
                    continue
                elif testapplication_package.search(path) is not None:
                    print("Snyk: Skipping:" + path)
                    continue
                else:
                    for vuln in vulnList:
                        vuln.pop('semver')
                        vulnArray.append(vuln)
            else:
                if target == 'vulnerabilities':
                    vulnList = content.get('vulnerabilities')
                    path = content.get('displayTargetFile')
                    print("Snyk path: {}".format(path))
                    if test_package.search(path) is not None:
                        print("Snyk: Skipping:" + path)
                        continue
                    elif benchmark_package.search(path) is not None:
                        print("Snyk: Skipping:" + path)
                        continue
                    elif examples_package.search(path) is not None:
                        print("Snyk: Skipping:" + path)
                        continue
                    elif testapplication_package.search(path) is not None:
                        print("Snyk: Skipping:" + path)
                        continue
                    else:
                        for vuln in vulnList:
                            vuln.pop('semver')
                            vulnArray.append(vuln)
                            print("1")
    else:
        global repoWithError
        repoWithError.append(os.path.basename(content['path']))
    return vulnArray

def formatTrivy(repository):
    index = repository.find("{")
    repo = repository[index:]
    TrivyRepo = json.loads(repo)
    results = TrivyRepo.get("Results")
    vulnArray = []
    if results is not None:
        for target in results:
            path = target.get("Target")
            if test_package.search(path) is not None:
                print("Trivy: Skipping:" + path)
                continue
            elif benchmark_package.search(path) is not None:
                print("Trivy: Skipping:" + path)
                continue
            elif examples_package.search(path) is not None:
                print("Trivy: Skipping:" + path)
                continue
            else:
                vulnTarget = target.get("Vulnerabilities", [])
                if not vulnTarget:
                    continue
                for vuln in vulnTarget:
                    vuln["Path"] = path
                vulnArray.extend(vulnTarget)
    return vulnArray

def get_vulnerabilities_by_directory(formatted_data):
        vulnerabilities_by_directory = defaultdict(list)
        
        for vuln in formatted_data:
                path = vuln.get("artifact").get("locations")[0].get("path")
                directory = os.path.dirname(path)
                vulnerabilities_by_directory[directory].append(vuln)

        return vulnerabilities_by_directory

def save_vulnerabilities_by_directory(vulnerabilities_by_directory, base_dir="./ONOS"):
    for directory, vulnerabilities in vulnerabilities_by_directory.items():
        
        clean_directory = re.sub(r'[^a-zA-Z0-9_\-]', '', directory)
        dir_path = os.path.join(base_dir, clean_directory)
        os.makedirs(dir_path, exist_ok=True)
        
        filename = "Grype.txt"
        filepath = os.path.join(dir_path, filename)
        
        with open(filepath, 'w') as json_file:
            json.dump(vulnerabilities, json_file, separators=(',', ':'))
        
        

def dump_scan_results(rics, sca_tools):
    scan_results = dict.fromkeys(rics)
    onos_repos = []
    osc_repos = []
    for ric in rics:
        ric_dir = "./" + ric
        if not os.path.exists(ric_dir):
            os.makedirs(ric_dir)
        for repository in sorted(os.listdir(ric_dir)):
            if ric == "ONOS":
                onos_repos.append(repository)
            elif ric == "OSC":
                osc_repos.append(repository)
    for ric in rics:
        if ric == "ONOS":
            scan_results[ric] = dict.fromkeys(onos_repos)
        elif ric == "OSC":
            scan_results[ric] = dict.fromkeys(osc_repos)
        for repository in sorted(os.listdir("./" + ric)):
            scan_results[ric][repository] = dict.fromkeys(sca_tools)
            path_to_repository = os.path.join("./" + ric, repository)
            for sca_tool_file in sorted(os.listdir(path_to_repository)):
                sca_tool_file_path = os.path.join(path_to_repository, sca_tool_file)
                with open(sca_tool_file_path) as file:
                    vuln = file.read()
                scan_results[ric][repository][sca_tool_file] = vuln
    with open('sca_results.json', 'w') as file:
        json.dump(scan_results, file)
    print("Finished writing: " + 'sca_results.json')
    pprint.pprint(scan_results)
    return scan_results

# Define the get_cves_cvss_dependencies function
def get_cves_cvss_dependencies(sca_tool, sca_tool_data):
    cves_cvss_dependencies = []
    cves = []
    cvss = []
    packages = []
    if sca_tool == "Grype.txt":
        for vulnerability in sca_tool_data:
            if vulnerability.get("vulnerability").get("id") not in cves:
                cves.append(vulnerability.get("vulnerability").get("id"))
                cvss_info = vulnerability.get("vulnerability").get("cvss")
                if cvss_info and len(cvss_info) > 0:
                    cvss.append(cvss_info[0].get("metrics").get("baseScore"))
                else:
                    cvss.append(None)  # or handle as you prefer
                    print(f"Vulnerability without CVSS: {vulnerability.get('vulnerability').get('id')}")
                vulnerability_match_details = vulnerability.get("matchDetails")
                for match_detail in vulnerability_match_details:
                    if "package" in match_detail["searchedBy"].keys():
                        packages.append(match_detail["searchedBy"]["package"]["name"])
                    elif "Package" in match_detail["searchedBy"].keys():
                        packages.append(match_detail["searchedBy"]["Package"]["name"])
            else:
                continue
        cves_cvss_dependencies = [cves, cvss, packages]
        return cves_cvss_dependencies
    elif sca_tool == "Snyk.txt":
        for vulnerability in sca_tool_data:
            if len(vulnerability.get("identifiers").get("CVE")) == 0:
                continue
            else:
                if vulnerability.get("identifiers").get("CVE")[0] not in cves:
                    cves.append(vulnerability.get("identifiers").get("CVE")[0])
                    cvss.append(vulnerability.get("cvssScore"))
                    packages.append(vulnerability.get("moduleName"))
        cves_cvss_dependencies = [cves, cvss, packages]
        return cves_cvss_dependencies
    elif sca_tool == "Trivy.txt":
        for vulnerability in sca_tool_data:
            if vulnerability.get("VulnerabilityID") not in cves:
                if vulnerability.get("CVSS") is not None:
                    cves.append(vulnerability.get("VulnerabilityID"))
                    packages.append(vulnerability.get("PkgName"))
                    nvd = vulnerability.get("CVSS").get("nvd")
                    ghsa = vulnerability.get("CVSS").get("ghsa")
                    if nvd is not None:
                        cvss.append(nvd.get("V3Score"))
                        continue
                    elif ghsa is not None:
                        cvss.append(ghsa.get("V3Score"))
                        continue
                else:
                    print(f"Vulnerability without CVSS: {vulnerability.get('VulnerabilityID')}")
                    continue
        cves_cvss_dependencies = [cves, cvss, packages]
        return cves_cvss_dependencies
    else:
        print("Unknown tool")
    return cves_cvss_dependencies


def extract_cves():
    # First read out the data
    scan_results_json = os.path.join(path_to_results + scan_results_file)
    sca_results = {}
    sca_cvecvss_dependencies = {}
    with open(scan_results_json) as file:
        sca_results = json.load(file)
    print("Finished reading the sca results file.")
    sca_cvecvss_dependencies = dict.fromkeys(rics)
    for ric in sca_results.keys():
        # Create repos as keys
        sca_cvecvss_dependencies[ric] = dict.fromkeys(sca_results[ric].keys())
        for repository in sca_results[ric].keys():
            sca_cvecvss_dependencies[ric][repository] = dict.fromkeys(sca_results[ric][repository].keys())
            print(repository)
            for sca_tool in sca_results[ric][repository].keys():
                sca_cvecvss_dependencies[ric][repository][sca_tool] = get_cves_cvss_dependencies(sca_tool, sca_results[ric][repository][sca_tool])
                print("Comparing length of cve and cvss lists.\n"
                    "RIC: {}, Repository: {}, SCA_Tool: {}, CVE len: {}, CVSS len: {}".format(ric, repository, sca_tool,
                                                                                              len(sca_cvecvss_dependencies[ric][repository][sca_tool][0]), len(sca_cvecvss_dependencies[ric][repository][sca_tool][1])))
                if len(sca_cvecvss_dependencies[ric][repository][sca_tool][0]) != len(sca_cvecvss_dependencies[ric][repository][sca_tool][1]):
                    print("More CVSS than CVE")
    print("Printing sca_cvecvss_dependencies results...")
    pprint.pprint(sca_cvecvss_dependencies)
    with open(path_to_results + 'sca_cvecvss_dependencies_results.json', 'w') as file:
        json.dump(sca_cvecvss_dependencies, file)
    print("Finished writing: " + path_to_results + 'sca_cvecvss_dependencies_results.json')



def main():
    parser = argparse.ArgumentParser(description='Format SCA tool data')
    parser.add_argument('data_file', type=str, help='Path to the data file in JSON format')
    parser.add_argument('tool', type=str, choices=['Grype.txt', 'Snyk.txt', 'Trivy.txt'], help='SCA tool used')
    args = parser.parse_args()

    with open(args.data_file, 'r') as file:
        data = file.read()

    formatted_data = format_sca_tool_data(data, args.tool)
    vulnerabilities_by_directory = get_vulnerabilities_by_directory(formatted_data)
    save_vulnerabilities_by_directory(vulnerabilities_by_directory)
    dump_scan_results(['ONOS', 'OSC'], ['Grype.txt'])


if __name__ == "__main__":
    main()