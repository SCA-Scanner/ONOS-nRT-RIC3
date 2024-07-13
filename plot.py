import json
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
import pprint

# RICs
rics = ['ONOS', 'OSC']

# Define the provided functions

def tabulate_cve_count(cve_data):
    cve_counts = {}
    for ric in cve_data.keys():
        total_cve_count = 0
        for repository in cve_data[ric]:
            total_cve_count += cve_data[ric][repository][0]
        cve_counts[ric] = total_cve_count
        print("RIC: " + str(ric) + " TOTAL CVEs: " + str(total_cve_count))
    return cve_counts


def tabulate_cvss(low_cve_data, medium_cve_data, high_cve_data, critical_cve_data):
    cvss_counts = {
        'low': {},
        'medium': {},
        'high': {},
        'critical': {}
    }
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
        cvss_counts['low'][ric] = low_cve_count
        cvss_counts['medium'][ric] = medium_cve_count
        cvss_counts['high'][ric] = high_cve_count
        cvss_counts['critical'][ric] = critical_cve_count
        print("RIC: " + str(ric) + " TOTAL Low CVEs: " + str(low_cve_count))
        print("RIC: " + str(ric) + " TOTAL Medium CVEs: " + str(medium_cve_count))
        print("RIC: " + str(ric) + " TOTAL High CVEs: " + str(high_cve_count))
        print("RIC: " + str(ric) + " TOTAL Critical CVEs: " + str(critical_cve_count))
    return cvss_counts

def plot_cvss_distribution(cvss_counts):
    fig, ax = plt.subplots(figsize=(10, 6))
    categories = ['low', 'medium', 'high', 'critical']
    ric_names = list(cvss_counts['low'].keys())
    bar_width = 0.2

    index = np.arange(len(ric_names))

    for i, category in enumerate(categories):
        counts = [cvss_counts[category][ric] for ric in ric_names]
        ax.bar(index + i * bar_width, counts, bar_width, label=category.capitalize())

    ax.set_xlabel('RICs')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('Distribution of CVSS Scores')
    ax.set_xticks(index + bar_width * 1.5)
    ax.set_xticklabels(ric_names, rotation=45, ha='right')
    ax.legend()

    plt.tight_layout()
    plt.savefig("cvss_distribution.pdf")
    plt.show()

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
    
    return packages_per_ric_repo, packages_per_ric

def plot_package_distribution(packages_per_ric):
    fig, ax = plt.subplots(figsize=(10, 6))
    ric_names = list(packages_per_ric.keys())
    package_counts = [len(packages_per_ric[ric]) for ric in ric_names]

    ax.bar(ric_names, package_counts, color='skyblue')

    ax.set_xlabel('RICs')
    ax.set_ylabel('Number of Packages')
    ax.set_title('Distribution of Vulnerable Dependency Packages')

    plt.tight_layout()
    plt.savefig("package_distribution.pdf")
    plt.show()

def plot_packages_per_repo(packages_per_ric_repo):
    fig, ax = plt.subplots(figsize=(10, 6))
    for ric in packages_per_ric_repo.keys():
        repositories = list(packages_per_ric_repo[ric].keys())
        package_counts = [packages_per_ric_repo[ric][repo][0]['unique_packages'] for repo in repositories]
        ax.bar(repositories, package_counts, label=ric)

    ax.set_xlabel('Repositories')
    ax.set_ylabel('Number of Unique Packages')
    ax.set_title('Vulnerable Dependency Packages per Repository')
    ax.legend()

    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig("packages_per_repo.pdf")
    plt.show()

# Load the necessary data
with open('per_ric_per_repo_cve_count.json', 'r') as file:
    cve_data = json.load(file)
with open('per_ric_per_repo_low_cves.json', 'r') as file:
    low_cve_data = json.load(file)
with open('per_ric_per_repo_medium_cves.json', 'r') as file:
    medium_cve_data = json.load(file)
with open('per_ric_per_repo_high_cves.json', 'r') as file:
    high_cve_data = json.load(file)
with open('per_ric_per_repo_critical_cves.json', 'r') as file:
    critical_cve_data = json.load(file)

# Generate the plots
cve_counts = tabulate_cve_count(cve_data)
cvss_counts = tabulate_cvss(low_cve_data, medium_cve_data, high_cve_data, critical_cve_data)
plot_cvss_distribution(cvss_counts)

# Load the CVSS data again for package distribution analysis
with open('sca_cvecvss_dependencies_results.json', 'r') as file:
    cvss_data = json.load(file)

packages_per_ric_repo, packages_per_ric = package_distribution_analysis(cvss_data)
plot_package_distribution(packages_per_ric)
plot_packages_per_repo(packages_per_ric_repo)
