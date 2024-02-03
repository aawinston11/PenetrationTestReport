# Introduction

In accordance with Catna policies, our organization conducts external and internal penetration tests of its networks and systems throughout the year. The purpose of this engagement was to assess the networks’ and systems’ security and identify potential security flaws by utilizing industry-accepted testing methodology and best practices.

For the testing, we focused on the following:

- Attempting to determine what system-level vulnerabilities could be discovered and exploited with no prior knowledge of the environment or notification to administrators.
- Attempting to exploit vulnerabilities found and access confidential information that may be stored on systems.
- Documenting and reporting on all findings.

All tests took into consideration the actual business processes implemented by the systems and their potential threats; therefore, the results of this assessment reflect a realistic picture of the actual exposure levels to online hackers. This document contains the results of that assessment.

## Assessment Objective

The primary goal of this assessment was to provide an analysis of security flaws present in Catna’s web applications, networks, and systems. This assessment was conducted to identify exploitable vulnerabilities and provide actionable recommendations on how to remediate the vulnerabilities to provide a greater level of security for the environment.

We used our proven vulnerability testing methodology to assess all relevant web applications, networks, and systems in scope. 

Catna has outlined the following objectives:

1. Find and exfiltrate any sensitive information within the domain.
2. Escalate privileges.
3. Compromise several machines.

# Penetration Testing Methodology

## Reconnaissance
 
We begin assessments by checking for any passive (open source) data that may assist the assessors with their tasks. If internal, the assessment team will perform active recon using tools such as Nmap and Bloodhound.

## Identification of Vulnerabilities and Services

We use custom, private, and public tools such as Metasploit, hashcat, and Nmap to gain perspective of the network security from a hacker’s point of view. These methods provide Catna with an understanding of the risks that threaten its information, and also the strengths and weaknesses of the current controls protecting those systems. The results were achieved by mapping the network architecture, identifying hosts and services, enumerating network and system-level vulnerabilities, attempting to discover unexpected hosts within the environment, and eliminating false positives that might have arisen from scanning. 

## Vulnerability Exploitation

Our normal process is to both manually test each identified vulnerability and use automated tools to exploit these issues. Exploitation of a vulnerability is defined as any action we perform that gives us unauthorized access to the system or the sensitive data. 

## Reporting

Once exploitation is completed and the assessors have completed their objectives, or have done everything possible within the allotted time, the assessment team writes the report, which is the final deliverable to the customer.


## Scope

Prior to any assessment activities, Catna and the assessment team will identify targeted systems with a defined range or list of network IP addresses. The assessment team will work directly with the Catna POC to determine which network ranges are in-scope for the scheduled assessment. 

It is Catna’s responsibility to ensure that IP addresses identified as in-scope are actually controlled by Catna and are hosted in Catna-owned facilities (i.e., are not hosted by an external organization). In-scope and excluded IP addresses and ranges are listed below. 


# Executive Summary of Findings

## Grading Methodology

Each finding was classified according to its severity, reflecting the risk each such vulnerability may pose to the business processes implemented by the application, based on the following criteria:

- Critical:	 Immediate threat to key business processes.
- High:		 Indirect threat to key business processes/threat to secondary business processes.
- Medium:	 Indirect or partial threat to business processes. 
- Low:		 No direct threat exists; vulnerability may be leveraged with other vulnerabilities.
- Informational:    No threat; however, it is data that may be used in a future attack.

## Summary of Strengths

While the assessment team was successful in finding several vulnerabilities, the team also recognized several strengths within Catna’s environment. These positives highlight the effective countermeasures and defenses that successfully prevented, detected, or denied an attack technique or tactic from occurring. 

- Not all Metasploit attempts were successful.
- Some passwords were not weak. 
- Used AAW Pen Test as a resource to identify vulnerabilities 


## Summary of Weaknesses

We successfully found several critical vulnerabilities that should be immediately addressed in order to prevent an adversary from compromising the network. These findings are not specific to a software version but are more general and systemic vulnerabilities.

- Open Ports
- Web App vulnerable to SQL Payload and XSS, stored and reflected
- Credentials are stored in HTML
- Weak User Passwords
- Sensitive Data Exposure
- Command Injection
- Outdated Apache Web Server
- Credentials in plain text
- Directory Traversal
- Use of SLMail Server
