import json
import sys

import os

base_main_path = os.getenv('BASE_MAIN_JSON')
commit_path = os.getenv('COMMIT_JSON')

introduced_vulnerabilities = []
with open(base_main_path, "r") as base_main:
    with open(commit_path, "r") as commit:
        base_main_data = json.load(base_main)
        commit_data = json.load(commit)
        for i in commit_data["runs"][0]["results"]:
            found = False
            for j in base_main_data["runs"][0]["results"]:
                if i["fingerprints"]["0"] == j["fingerprints"]["0"]:
                    found = True
            if found == False:
                introduced_vulnerabilities.append(i)
vulnerabilities_to_return = []
for vulnerability in introduced_vulnerabilities:
    vulnerability_score = vulnerability["properties"]["priorityScore"]
    if vulnerability_score >= 900:
        vulnerability_priority = "Critical"
    elif vulnerability_score >= 700:
        vulnerability_priority = "High"
    elif vulnerability_score >= 400:
        vulnerability_priority = "Medium"
    else:
        vulnerability_priority = "Low"
    if vulnerability_score >= 700:
        vulnerability_string = ""
        print("\n")
        print("[" + vulnerability_priority + "] " + vulnerability["ruleId"])
        vulnerability_line = vulnerability["locations"][0]["physicalLocation"]["region"]["startLine"]
        if vulnerability_line != vulnerability["locations"][0]["physicalLocation"]["region"]["endLine"]:
            vulnerability_line += "-" + vulnerability["locations"][0]["physicalLocation"]["region"]["endLine"]
        print("Path: " + vulnerability["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] + ", line: " + str(vulnerability_line))
        print("Info: " + vulnerability["message"]["text"] + "\n")
        print("\n")
if len(introduced_vulnerabilities) > 0:
    sys.exit(1)