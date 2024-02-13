
# Common Vulnerability Scoring System
The CVSS is a scoring system used to score the severity of a [CVE](cybersecurity/resources/CVEs.md) based on a few metrics. The CVSS qualitatively measures *severity and not risk*. The three metrics involved in calculating a CVSS is Base, Temporal, and Environmental:
## Base Scoring Metric
The base score is set between 1 and 10. This score is the severity the CVE is given before considering the other two metrics. Based on the Temporal and Environment metrics, the Base score will change.

The Base score is made up of a few sub-metrics, each of which describes either the *exploitability or impact* of the vulnerability.
### Exploitability Metrics:
#### Attack Vector
Refers to how an attacker can deliver an exploit to the vulnerability. The options include. The Base increases the more remote an attacker is able to be to exploit.
- *Network*
- Adjacent Network
- Local
- Physical
#### Attack Complexity
How complex are the steps an attacker would have to take in order to exploit this vulnerability? Low complexity increases the severity.
- *Low*
- High
#### Privilege Required
Is privilege required? If so, is the privilege level high or low? None or low privilege increases the severity.
- *None*
- Low
- High
#### User Interaction
Does the vulnerability rely on a third victim-party to take an action in order for it to be exploited? If a third-party or user does not need to take any action for the attacker to exploit the vuln, the severity increases.
- *None*
- Required
### Impact Metrics:
#### Scope:
Can an attacker use this vulnerability to effect components which are not the vulnerable one? i.e. is the potential impact localized to the vulnerable component? The more components the vulnerability can effect beyond the local system, the more severe the vuln is.
- *Changed* (can impact systems beyond the vulnerable one)
- Unchanged (impact is localized)
#### Confidentiality
Is there any impact to the confidentiality of resources/ information? The more information, especially critical information, the vuln allows an attacker to access, the more severe the vuln is.
- *High* (all information)
- Low
- None
#### Integrity Impact
Can the attacker *modify* the information they have access to via this vuln? the more information they can modify, the more severe the score will be.
- *High* (can modify any non-critical and/or *some critical* information)
- Low
- None
#### Availability Impact
Will exploiting this vuln cause any impact to the availability of a resource? I.e. can the attacker (at worst) completely deny access to the effected component, and if so, how critical is that component?
- *High* (effected resources is completely unavailable)
- Low
- None
## Temporal
The Temporal metrics are intended to capture the *relevance of the vulnerability* based on current techniques, code maturity, patches, workarounds, report confidence, and remediation.

The Temporal metric *is expected to change overtime* since it accounts for the *current* state of the vulnerability.
### Exploit Code Maturity
This sub-metric of the Temporal score describes whether this vulnerability and/or exploit *is currently being used in the wild.* It measures the availability, reliability, functionality, and ease-of-use *of the actual code required to carry out an exploit*.

This score is important because *most exploits are theoretical* and not actually seen being used by attackers. It's important to capture this feature of the environment because *most hackers are very unskilled* and thus less likely to use complex, theoretical exploits.

The impact of this metric on the Base Score can be drastic. For example:
![](cybersecurity/cybersecurity-pics/CVSS-1.png)
> [Balbix](https://www.balbix.com/insights/temporal-cvss-scores/)

This image shows a CVE with a base score of 6.8. Once it's been determined that the exploit code *doesn't exist* and the vendor *has released a widely-available patch* the score decreases to 5.5.

There are 5 submetrics to determine Exploit Code Maturity. The more widely available, functional, and proven the exploit code is the more severe the CVSS will be.
#### Not Defined
There isn't enough information to assign a Temporal score, so this value doesn't impact it.
#### High
The exploit code is widely available, reliable, easy to use, and functional.
#### Functional
The exploit code is available and is somewhat reliable.
#### Proof of Concept
The code exists but may or may not be reliable and likely requires a very skilled attacker to be used successfully.
#### Unproven
The exploit *is theoretical only* and the actual code *is not known to exist.*
### Remediation Level
This metric describes the *availability and maturity* of patches and other fixes for the vuln. As remediations mature or improve, this score will decrease.

There are 5 levels which impact this score:
#### Not Defined
(see above)
#### Unavailable
There is no patch or other mitigation available.
#### Workaround
There is either an unofficial patch, or there are other steps and/or configurations which can be done to mitigate.
#### Temporary Fix
The vendor has created a fix or patch, but it is only temporary.
#### Official Fix
The vendor has made available either a permanent patch for the vuln, or the vuln is rendered benign via updating the product.
### Report Confidence
This metric describes *the confidence that the vulnerability actually exists*. It takes into consideration the details of the reported issue and whether the vendor has publicly acknowledged the vuln. The more confidences there is in its existence, the more severe the overall score will be.

The four levels used to score report confidence are:
#### Not Defined
(see above)
#### Confirmed
Either the vendor has confirmed that the vulnerability exists, the reproduction of the vuln has been proven (not theoretical), or the source code is available to confirm the vuln.
#### Reasonable
Details about the vuln have been published but not verified.
#### Unknown
There may be reports and/or rumors that the vuln exists, but the validity of the reports is questionable and not consistent.
## Environmental
This metric modifies the Base metric by taking into account how the base metric changes r/t environmental factors of an enterprise. It's made up of Modified Base Metrics and Security Requirements:
### Modified Base Metrics
This metric allows the original Base metrics to be modified *based on the user's specific environment*. It's scored individually by each enterprise wishing to re-assess the severity of a CVE in their own environment.

For example, if an enterprise has [firewalls](/cybersecurity/defense/firewalls.md) up as mitigation, then their base scare can be modified to reflect a lower severity for their environment.
### Security Requirements
This metric is used to determining the criticality of a business's asset. The criticality is measured using the *CIA triad* which is made up of confidentiality, integrity, and availability.

Each requirement is assigned 1 of 4 values to measure their individual severity. The more important and/ or impactful the loss of each requirement is, the more severe the CVE is rated for that organization.
- Not Defined (see above)
- *High:* the loss of confidentiality, integrity, and/ or availability would have catastrophic impact on the organization
- Medium: the loss of either of these would have a serious adverse effect on the org.
- Low: loss of either of these would have a limited and/ or isolated impact on the org.
#### Confidentiality Requirement
Confidentiality is the ability to hide sensitive information from users who aren't authorized to access it.
#### Integrity Requirement
This describes the ability of the organization to protect the information from being changed/ modified from its original state.
#### Availability Requirement
This describes the availability of the information to authorized users as they need it.
### Environmental Metric Impact
In this example, a CVE has been given a CVSS of 9.9 (after the Base and Temporal metrics have been graded). With aggressive environmental controls and mitigations, the Environmental Metric is scored as a 3.2, bringing the overall CVSS *down from 9.9 to 3.2*.
![](cybersecurity/cybersecurity-pics/CVSS-2.png)
> [Balbix](https://www.balbix.com/insights/environmental-cvss-scores/)

> [!Resources]
> - [NIST: Vulnerability Metrics](https://nvd.nist.gov/vuln-metrics/cvss)
> - [First: CVSS v3.1 User Guide](https://www.first.org/cvss/user-guide)
> - [Balbix: Temporal CVSS Scored](https://www.balbix.com/insights/temporal-cvss-scores/)
> - [Balbix: Environmental CVSS Scores](https://www.balbix.com/insights/environmental-cvss-scores/)