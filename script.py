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
            print("Grype: Skipping")
            continue
        elif benchmark_package.search(path) is not None:
            print("Grype: Skipping")
            continue
        elif examples_package.search(path) is not None:
            print("Grype: Skipping")
            continue
        elif testapplication_package.search(path) is not None:
            print("Grype: Skipping")
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

def save_vulnerabilities_by_directory(vulnerabilities_by_directory, base_dir="./ONOS"):
    for directory, vulnerabilities in vulnerabilities_by_directory.items():
        clean_directory = re.sub(r'[^a-zA-Z0-9_\-]', '_', directory)
        dir_path = os.path.join(base_dir, clean_directory)
        os.makedirs(dir_path, exist_ok=True)
        
        filename = "vulnerabilities.json"
        filepath = os.path.join(dir_path, filename)
        
        with open(filepath, 'w') as json_file:
            json.dump(vulnerabilities, json_file, indent=4)

def dump_scan_results():
    scan_results = dict.fromkeys(rics)
    onos_repos = []
    osc_repos = []
    for ric in rics:
        for repository in sorted(os.listdir("." + ric)):
            if ric == "ONOS":
                onos_repos.append(repository)
            elif ric == "OSC":
                osc_repos.append(repository)
    for ric in rics:
        if ric == "ONOS":
            scan_results[ric] = dict.fromkeys(onos_repos)
        elif ric == "OSC":
            scan_results[ric] = dict.fromkeys(osc_repos)
        for repository in sorted(os.listdir("." + ric)):
            scan_results[ric][repository] = dict.fromkeys(sca_tools)
            print("In repository:" + repository)
            path_to_repository = os.path.join("." + ric, repository)
            for sca_tool_file in sorted(os.listdir(path_to_repository)):
                sca_tool_file_path = os.path.join(path_to_repository, sca_tool_file)
                with open(sca_tool_file_path) as file:
                    vuln = file.read()
                scan_results[ric][repository][sca_tool_file] = vuln
    with open("." + 'sca_results.json', 'w') as file:
        json.dump(scan_results, file)
    print("Finished writing: " + "." + 'sca_results.json')

def main():
    parser = argparse.ArgumentParser(description='Format SCA tool data')
    parser.add_argument('data_file', type=str, help='Path to the data file in JSON format')
    parser.add_argument('tool', type=str, choices=['Grype.txt', 'Snyk.txt', 'Trivy.txt'], help='SCA tool used')
    args = parser.parse_args()

    with open(args.data_file, 'r') as file:
        data = file.read()

    vulnerabilities_by_directory = defaultdict(list)
    formatted_data = format_sca_tool_data(data, args.tool)
    for vuln in formatted_data:
        path = vuln.get("artifact").get("locations")[0].get("path")
        directory = os.path.dirname(path)
        vulnerabilities_by_directory[directory].append(vuln)

    save_vulnerabilities_by_directory(vulnerabilities_by_directory)
    dump_scan_results()

if __name__ == "__main__":
    main()
