import matplotlib.pyplot as plt
import json
import os
from collections import defaultdict, Counter
from script import extract_cves, per_repo_cve_count, cvss_distribution, package_distribution_analysis 
# Assuming you have a processed JSON file 'sca_results.json'
with open('sca_results.json', 'r') as file:
    sca_results = json.load(file)

# Extract CVEs and CVSS dependencies
sca_cvecvss_dependencies_results = extract_cves(sca_results)

# Count CVEs per RIC and repository
cve_per_ric_repo_tool, cve_per_ric_repo = per_repo_cve_count(sca_cvecvss_dependencies_results)

# CVSS distribution analysis
low_cvss_per_ric_repo, medium_cvss_per_ric_repo, high_cvss_per_ric_repo, critical_cvss_per_ric_repo, cve_per_ric_repo = cvss_distribution(sca_cvecvss_dependencies_results)

# Package distribution analysis
packages_per_ric_repo, packages_per_ric = package_distribution_analysis(sca_cvecvss_dependencies_results)


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

# Plot Vulnerabilities per Repository of each RIC
for ric, repos in vulnerabilities_per_repo.items():
    plt.figure()
    plt.bar(repos.keys(), repos.values())
    plt.title(f'Vulnerabilities per Repository for {ric}')
    plt.xlabel('Repository')
    plt.ylabel('Number of Vulnerabilities')
    plt.show()


# Plot Distribution of Severity Scores
for ric, severity in severity_distribution.items():
    plt.figure()
    plt.bar(severity.keys(), severity.values())
    plt.title(f'Severity Distribution for {ric}')
    plt.xlabel('Severity')
    plt.ylabel('Number of Vulnerabilities')
    plt.show()

