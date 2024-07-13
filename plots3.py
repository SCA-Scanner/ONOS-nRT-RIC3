import matplotlib.pyplot as plt
import json
import os
from collections import defaultdict, Counter
from script import extract_cves, per_repo_cve_count, cvss_distribution, package_distribution_analysis 
# Assuming you have a processed JSON file 'sca_results.json'
with open('sca_results.json', 'r') as file:
    sca_results = json.load(file)

# Set the directory containing the matplotlibrc file
os.environ['MPLCONFIGDIR'] = 'matplotlibrc'

# Extract CVEs and CVSS dependencies
sca_cvecvss_dependencies_results = extract_cves(sca_results)

# Count CVEs per RIC and repository
cve_per_ric_repo_tool, cve_per_ric_repo = per_repo_cve_count(sca_cvecvss_dependencies_results)

# CVSS distribution analysis
low_cvss_per_ric_repo, medium_cvss_per_ric_repo, high_cvss_per_ric_repo, critical_cvss_per_ric_repo, cve_per_ric_repo = cvss_distribution(sca_cvecvss_dependencies_results)

# Package distribution analysis
packages_per_ric_repo, packages_per_ric = package_distribution_analysis(sca_cvecvss_dependencies_results)

# Helper function to count total CVEs per RIC
def count_total_cves(low, medium, high, critical):
    total_cves = {ric: sum(len(low[ric][repo][1]) + len(medium[ric][repo][1]) + len(high[ric][repo][1]) + len(critical[ric][repo][1]) for repo in low[ric].keys()) for ric in low.keys()}
    return total_cves

# Count total CVEs per RIC
total_vulnerabilities_ric = count_total_cves(low_cvss_per_ric_repo, medium_cvss_per_ric_repo, high_cvss_per_ric_repo, critical_cvss_per_ric_repo)

# Prepare data for vulnerabilities per repository
vulnerabilities_per_repo = {ric: {repo: len(cves_without_dups) for repo, (_, cves_without_dups) in repos.items()} for ric, repos in cve_per_ric_repo.items()}



# Prepare data for severity distribution
severity_distribution = {
    ric: {
        'low': sum(len(low_cvss_per_ric_repo[ric][repo][1]) for repo in repos.keys()),
        'medium': sum(len(medium_cvss_per_ric_repo[ric][repo][1]) for repo in repos.keys()),
        'high': sum(len(high_cvss_per_ric_repo[ric][repo][1]) for repo in repos.keys()),
        'critical': sum(len(critical_cvss_per_ric_repo[ric][repo][1]) for repo in repos.keys())
    }
    for ric, repos in sca_cvecvss_dependencies_results.items()
}

# Prepare data for vulnerable packages
vulnerable_packages_per_ric = {ric: len(packages) for ric, packages in packages_per_ric.items()}

# Prepare data for vulnerable packages per repository
vulnerable_packages_per_repo = {
    ric: {repo: packages_info[0]['unique_packages'] for repo, packages_info in repos.items()}
    for ric, repos in packages_per_ric_repo.items()
}

# Plot Total number of vulnerabilities per RIC
plt.figure()
plt.bar(total_vulnerabilities_ric.keys(), total_vulnerabilities_ric.values(), color='skyblue')
plt.title('Total Number of Vulnerabilities per RIC')
plt.xlabel('RIC')
plt.ylabel('Number of Vulnerabilities')
plt.grid(axis='y')
plt.savefig('total_vulnerabilities_per_ric.png', dpi=300)
plt.show()

# Plot Vulnerabilities per Repository of each RIC
for ric, repos in vulnerabilities_per_repo.items():
    plt.figure(figsize=(14, 8))
    plt.bar(repos.keys(), repos.values(), color='lightgreen')
    plt.title(f'Vulnerabilities per Repository for {ric}')
    plt.xlabel('Repository')
    plt.ylabel('Number of Vulnerabilities')
    plt.xticks(rotation=90)
    plt.grid(axis='y')
    plt.tight_layout()
    plt.savefig(f'vulnerabilities_per_repo_{ric}.png', dpi=300)
    plt.show()

# Plot Distribution of Severity Scores
for ric, severity in severity_distribution.items():
    plt.figure()
    plt.bar(severity.keys(), severity.values(), color=['lightblue', 'lightgreen', 'salmon', 'orange'])
    plt.title(f'Severity Distribution for {ric}')
    plt.xlabel('Severity')
    plt.ylabel('Number of Vulnerabilities')
    plt.grid(axis='y')
    plt.savefig(f'severity_distribution_{ric}.png', dpi=300)
    plt.show()

# Plot Distribution of vulnerable dependency packages
plt.figure(figsize=(10, 6))
plt.bar(vulnerable_packages_per_ric.keys(), vulnerable_packages_per_ric.values(), color='violet')
plt.title('Distribution of Vulnerable Dependency Packages per RIC')
plt.xlabel('RIC')
plt.ylabel('Number of Vulnerable Packages')
plt.grid(axis='y')
plt.savefig('vulnerable_packages_per_ric.png', dpi=300)
plt.show()

# Plot Vulnerable dependency packages per repository
for ric, repos in vulnerable_packages_per_repo.items():
    plt.figure(figsize=(14, 8))
    plt.bar(repos.keys(), repos.values(), color='lightcoral')
    plt.title(f'Vulnerable Dependency Packages per Repository for {ric}')
    plt.xlabel('Repository')
    plt.ylabel('Number of Vulnerable Packages')
    plt.xticks(rotation=90)
    plt.grid(axis='y')
    plt.tight_layout()
    plt.savefig(f'vulnerable_packages_per_repo_{ric}.png', dpi=300)
    plt.show()