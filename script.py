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


def extract_cves(sca_results):
    # Initialize the dictionary to store CVE and CVSS dependencies
    sca_cvecvss_dependencies = dict.fromkeys(rics)
    
    print("Finished reading the SCA results data.")
    
    for ric in sca_results.keys():
        # Create repos as keys
        sca_cvecvss_dependencies[ric] = dict.fromkeys(sca_results[ric].keys())
        for repository in sca_results[ric].keys():
            sca_cvecvss_dependencies[ric][repository] = dict.fromkeys(sca_results[ric][repository].keys())
            print(repository)
            for sca_tool in sca_results[ric][repository].keys():
                sca_tool_data_str = sca_results[ric][repository][sca_tool]
                sca_tool_data = json.loads(sca_tool_data_str)
                sca_cvecvss_dependencies[ric][repository][sca_tool] = get_cves_cvss_dependencies(sca_tool, sca_tool_data)
                print("Comparing length of CVE and CVSS lists.\n"
                      "RIC: {}, Repository: {}, SCA_Tool: {}, CVE len: {}, CVSS len: {}".format(
                          ric, repository, sca_tool,
                          len(sca_cvecvss_dependencies[ric][repository][sca_tool][0]), 
                          len(sca_cvecvss_dependencies[ric][repository][sca_tool][1])
                      ))
                if len(sca_cvecvss_dependencies[ric][repository][sca_tool][0]) != len(sca_cvecvss_dependencies[ric][repository][sca_tool][1]):
                    print("More CVSS than CVE")
    
    print("Printing sca_cvecvss_dependencies results...")
    pprint.pprint(sca_cvecvss_dependencies)
    
    # Return the results dictionary
    return sca_cvecvss_dependencies

def count_cves(cve_data):
    print("Going to count CVEs per repo and per RIC")

    # Initialize the dictionary to store CVE counts per RIC
    ric_cves = dict.fromkeys(rics)

    for ric in cve_data.keys():
        total_ric_cves = []
        for repository in cve_data[ric].keys():
            total_repo_cves = []
            for sca_tool in cve_data[ric][repository].keys():
                if sca_tool == "Scantist.json":
                    continue
                else:
                    print("RIC: {}, Repository: {}, SCA Tool: {}, total CVE Count: {}".format(
                        ric, repository, sca_tool, len(cve_data[ric][repository][sca_tool][0])
                    ))
                    # Append only unique CVEs to count total unique vulnerabilities for a repository
                    for cve in cve_data[ric][repository][sca_tool][0]:
                        if cve not in total_repo_cves:
                            total_repo_cves.append(cve)
            print("RIC: {}, Repository: {}, Total Repo CVEs: {}".format(ric, repository, len(total_repo_cves)))
            total_ric_cves.extend(total_repo_cves)
        ric_cves[ric] = total_ric_cves
    
    pprint.pprint(ric_cves)
    for ric in ric_cves.keys():
        print("RIC: {}, Total unique CVEs: {}".format(ric, len(ric_cves[ric])))


def per_repo_cve_count(cve_data):
    print("1. CVEs per RIC/repo/tool\n"
          "2. Total CVEs per RIC/repo with duplicates\n"
          "3. Total CVEs per RIC/repo without duplicates")
    
    # First CVEs per RIC/repo/tool
    cve_per_ric_repo_tool = dict.fromkeys(rics)
    for ric in cve_data.keys():
        cve_per_ric_repo_tool[ric] = dict.fromkeys(cve_data[ric].keys())
        for repository in cve_data[ric].keys():
            cve_per_ric_repo_tool[ric][repository] = dict.fromkeys(cve_data[ric][repository].keys())
            for sca_tool in cve_data[ric][repository].keys():
                if sca_tool == "Scantist.json":
                    continue
                else:
                    cve_per_ric_repo_tool[ric][repository][sca_tool] = len(cve_data[ric][repository][sca_tool][0])
    pprint.pprint(cve_per_ric_repo_tool)

    # Now combine the CVEs from all the tools and save two lists with_dups and without_dups
    cve_per_ric_repo = dict.fromkeys(rics)
    for ric in cve_data.keys():
        cve_per_ric_repo[ric] = dict.fromkeys(cve_data[ric].keys())
        for repository in cve_data[ric].keys():
            cve_list_with_dups = []
            cve_list_without_dups = []
            for sca_tool in cve_data[ric][repository].keys():
                if sca_tool == "Scantist.json":
                    continue
                else:
                    for cve in cve_data[ric][repository][sca_tool][0]:
                        cve_list_with_dups.append(cve)
                        if cve not in cve_list_without_dups:
                            cve_list_without_dups.append(cve)
            cve_per_ric_repo[ric][repository] = [cve_list_with_dups, cve_list_without_dups]
            print("Repository: {}".format(repository))
            print("Length with duplicates: {}".format(len(cve_list_with_dups)))
            print("Length without duplicates: {}".format(len(cve_list_without_dups)))

    return cve_per_ric_repo_tool, cve_per_ric_repo


def cvss_distribution(cvss_data):
    print("1. Print per RIC per repo per tool CVSS >= 8\n"
          "2. Print per RIC per repo CVSS >= 8")
    
    # Print total CVE and CVSS counts per RIC
    print("Going to compare CVE list and CVSS list and then count the number of CVSS")
    for ric in cvss_data.keys():
        total_cve_count = 0
        total_cvss_count = 0
        for repository in cvss_data[ric].keys():
            for sca_tool in cvss_data[ric][repository].keys():
                total_cve_count += len(cvss_data[ric][repository][sca_tool][0])
                total_cvss_count += len(cvss_data[ric][repository][sca_tool][1])
        print("RIC:{}, total_cve_count:{}, total_cvss_count:{}".format(ric, total_cve_count, total_cvss_count))

    # Initialize dictionaries for CVSS distribution
    low_cvss_per_ric_repo = dict.fromkeys(rics)
    medium_cvss_per_ric_repo = dict.fromkeys(rics)
    high_cvss_per_ric_repo = dict.fromkeys(rics)
    critical_cvss_per_ric_repo = dict.fromkeys(rics)
    cve_per_ric_repo = dict.fromkeys(rics)
    none_counter = 0
    
    for ric in cvss_data.keys():
        low_cvss_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        medium_cvss_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        high_cvss_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        critical_cvss_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        cve_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        
        for repository in cvss_data[ric].keys():
            low_cvss_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            medium_cvss_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            high_cvss_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            critical_cvss_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            cve_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            
            low_cves = []
            medium_cves = []
            high_cves = []
            critical_cves = []
            cves = []
            
            for sca_tool in cvss_data[ric][repository].keys():
                if sca_tool == "Scantist.json":
                    continue
                else:
                    for index, cvss in enumerate(cvss_data[ric][repository][sca_tool][1]):
                        cve = cvss_data[ric][repository][sca_tool][0][index]
                        if cvss is None:
                            none_counter += 1
                        elif 0.1 <= cvss <= 3.9:
                            print("Repository: {}, Tool: {}, CVE: {}, CVSS: {}".format(repository, sca_tool, cve, cvss))
                            if cve not in low_cves and cve not in medium_cves and cve not in high_cves and cve not in critical_cves:
                                low_cves.append(cve)
                            if cve not in cves:
                                cves.append(cve)
                        elif 4.0 <= cvss <= 6.9:
                            print("Repository: {}, Tool: {}, CVE: {}, CVSS: {}".format(repository, sca_tool, cve, cvss))
                            if cve not in low_cves and cve not in medium_cves and cve not in high_cves and cve not in critical_cves:
                                medium_cves.append(cve)
                            if cve not in cves:
                                cves.append(cve)
                        elif 7.0 <= cvss <= 8.9:
                            print("Repository: {}, Tool: {}, CVE: {}, CVSS: {}".format(repository, sca_tool, cve, cvss))
                            if cve not in low_cves and cve not in medium_cves and cve not in high_cves and cve not in critical_cves:
                                high_cves.append(cve)
                            if cve not in cves:
                                cves.append(cve)
                        elif 9.0 <= cvss <= 10.0:
                            print("Repository: {}, Tool: {}, CVE: {}, CVSS: {}".format(repository, sca_tool, cve, cvss))
                            if cve not in low_cves and cve not in medium_cves and cve not in high_cves and cve not in critical_cves:
                                critical_cves.append(cve)
                            if cve not in cves:
                                cves.append(cve)
            
            low_cvss_per_ric_repo[ric][repository] = [len(low_cves), low_cves]
            medium_cvss_per_ric_repo[ric][repository] = [len(medium_cves), medium_cves]
            high_cvss_per_ric_repo[ric][repository] = [len(high_cves), high_cves]
            critical_cvss_per_ric_repo[ric][repository] = [len(critical_cves), critical_cves]
            cve_per_ric_repo[ric][repository] = [len(cves), cves]
            total = len(low_cves) + len(medium_cves) + len(high_cves) + len(critical_cves)
            print("RIC: {}, Repository: {}, Total count: {}".format(ric, repository, total))
    
    print("Nonecounter: " + str(none_counter))
    
    return low_cvss_per_ric_repo, medium_cvss_per_ric_repo, high_cvss_per_ric_repo, critical_cvss_per_ric_repo, cve_per_ric_repo


def package_distribution_analysis(cvss_data):
    print("Analyzing package distribution...")

    # Initialize dictionaries for package distribution
    packages_per_ric_repo = dict.fromkeys(rics)
    packages_per_ric = dict.fromkeys(rics)
    
    for ric in cvss_data.keys():
        packages_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        ric_packages = []
        
        for repository in cvss_data[ric].keys():
            packages_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            packages = []
            unique_packages = []
            
            for sca_tool in cvss_data[ric][repository].keys():
                if sca_tool == "Scantist.json":
                    continue
                else:
                    for path in cvss_data[ric][repository][sca_tool][2]:
                        packages.append(path)
                        ric_packages.append(path)
                        if path not in unique_packages:
                            unique_packages.append(path)
            
            packages_per_ric_repo[ric][repository] = [{"unique_packages": len(unique_packages)}, dict(Counter(packages))]
        
        packages_per_ric[ric] = dict(Counter(ric_packages))
    
    # Sort and print package distributions
    onos = packages_per_ric["ONOS"]
    osc = packages_per_ric["OSC"]
    sorted_onos = sorted(onos.items(), key=lambda x: x[1], reverse=True)
    sorted_osc = sorted(osc.items(), key=lambda x: x[1], reverse=True)
    
    print("Sorted ONOS")
    pprint.pprint(sorted_onos)
    print("Sorted OSC")
    pprint.pprint(sorted_osc)
    
    print("Now to print per RIC per repo packages")
    pprint.pprint(packages_per_ric_repo)
    
    for ric in rics:
        for repo in packages_per_ric_repo[ric]:
            print("RIC: {}\tRepository: {}\t\tUnique packages: {}".format(ric, repo, packages_per_ric_repo[ric][repo][0]["unique_packages"]))
    
    return packages_per_ric_repo, packages_per_ric



def tabulate_cvss():
    low_cve_json_file = os.path.join(path_to_results + 'per_ric_per_repo_low_cves.json')
    medium_cve_json_file = os.path.join(path_to_results + 'per_ric_per_repo_medium_cves.json')
    high_cve_json_file = os.path.join(path_to_results + 'per_ric_per_repo_high_cves.json')
    critical_cve_json_file = os.path.join(path_to_results + 'per_ric_per_repo_critical_cves.json')
    low_cve_data = {}
    medium_cve_data = {}
    high_cve_data = {}
    critical_cve_data = {}
    with open(low_cve_json_file) as file:
        low_cve_data = json.load(file)
    with open(medium_cve_json_file) as file:
        medium_cve_data = json.load(file)
    with open(high_cve_json_file) as file:
        high_cve_data = json.load(file)
    with open(critical_cve_json_file) as file:
        critical_cve_data = json.load(file)
    for ric in low_cve_data.keys():
        low_cve_count = 0
        medium_cve_count = 0
        high_cve_count = 0
        critical_cve_count = 0
        for repository in low_cve_data[ric]:
            low_cve_count += low_cve_data[ric][repository][0]
        for repository in medium_cve_data[ric]:
            medium_cve_count += medium_cve_data[ric][repository][0]
        for repository in high_cve_data[ric]:
            high_cve_count += high_cve_data[ric][repository][0]
        for repository in critical_cve_data[ric]:
            critical_cve_count += critical_cve_data[ric][repository][0]
        print("RIC: " + str(ric) + " TOTAL Low CVEs: " + str(low_cve_count))
        print("RIC: " + str(ric) + " TOTAL Medium CVEs: " + str(medium_cve_count))
        print("RIC: " + str(ric) + " TOTAL High CVEs: " + str(high_cve_count))
        print("RIC: " + str(ric) + " TOTAL Critical CVEs: " + str(critical_cve_count))

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

    sca_results = dump_scan_results(['ONOS', 'OSC'], ['Grype.txt'])
    sca_cvecvss_dependencies_results = extract_cves(sca_results)


    count_cves(sca_cvecvss_dependencies_results)

    cve_per_ric_repo_tool, cve_per_ric_repo = per_repo_cve_count(sca_cvecvss_dependencies_results)

    low_cvss_per_ric_repo, medium_cvss_per_ric_repo, high_cvss_per_ric_repo, critical_cvss_per_ric_repo, cve_per_ric_repo = cvss_distribution(sca_cvecvss_dependencies_results)

    packages_per_ric_repo, packages_per_ric = package_distribution_analysis(sca_cvecvss_dependencies_results)


if __name__ == "__main__":
    main()