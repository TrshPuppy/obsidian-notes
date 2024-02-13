
# Endpoint Detection Response
EDR (also called ETDR: endpoint thread detection and response) is a security solution which focused on monitoring endpoint devices to detect threats like [ransomware](cybersecurity/TTPs/actions-on-objective/ransomware.md) and malware. There are a few things which EDR uses and/or does in order to detect and monitor for suspicious activity:
- data analytics
- block malicious activity
- provide contextual information
- restore effected systems
- provide suggestions for remediation
- investigation and response
- alert triage
- malicious activity detection and containment
EDR is a solution which 
> "...records and stores endpoint-system-level behaviors, uses various data analytics techniques to detect suspicious system behavior, provides contextual information, blocks malicious activity, and provides remediation suggestions to restore effected systems."

-Anton Chuvakin
## Functions
EDR works by recording activities and events on endpoints and other workloads. A good EDR solution reports *in real time* what is happening on all endpoints so that, in the case of a security breach, cybersecurity teams can quickly uncover what's happening and respond.

Part of what allows EDR to detect and alert about malicious activity is by collecting and aggregating data on and about the endpoints. Most EDRs are used as a *detection and alerting* system rather than a defensive or blocking system. However, some EDR solutions are able to provide defensive functions such as blocklists.
### Collecting Security Data
Most EDR systems deploy lightweight *'agents'* on endpoint devices which facilitate the collection on security data. These agents can collect information *even when the device isn't connected to the internet*. the type of telemetry they collect include things like:
- what processes are running
- what servers is the device connected to
- what files are open
This data is reported back in *real-time* but is also stored to be used in *forensic analysis* after malicious activity has occurred.
### Detecting & Responding to Threats
EDRs should be able to detect threats and respond to them in real-time. Most EDRs accomplish this within 2 scopes: threats which have been seen before, and new threats.
#### Threats seen before
When malicious activity occurs in the wild, IOCs (indicators of compromise) are collected about that threat. For example, a piece of malware that's been around for a while has specific traits which have been recorded and shared about it. In other words, the malware has a 'fingerprint'. EDR solutions can protect against and/or respond to known threats like this by using a database of known fingerprints for commonly-seen malware, etc.
#### New threats
Even if an EDR system encounters malicious activity *which has never been seen before and has no fingerprint* it's likely that this threat still uses *common recognizable TTPs*.

EDRs detect these types of threats by using advanced algorithms which *recognize malicious behaviors*. For example, a lot of malware hides itself in the macro code of a Microsoft Office file. Instead of detecting the malware itself (which is unknown) the EDR may scan for other *behaviors* the malware is likely to show, such as attempting to alter the system's security settings.
### Forensic Investigation & Threat Hunting
Because EDRs are unlikely to catch *every single* threat, a good EDR should assist security teams in the event that a threat is able to breach past it. EDRs collect a bunch of data and information *relevant to understanding how an attack was able to be carried out successfully.* This data can be used after the fact by a security team to help resolve the issue and mitigate against it in the future.

After a successful attack has been mounted, and the security team has discovered how it was carried out, that forensic information can also be used for *threat hunting*. Threat hunting in this case means proactively scanning other endpoints for evidence of that same attack and stopping it before it can be carried out.
### Integrate & Report
An EDR should be able to integrate into the security infrastructure of the organization. For example, a SOC analyst should be able to rely on an EDR to help them *prioritize incidents* and triage them by importance. The EDR should present them with *relevant information* in an easy to use interface.

Additionally, the EDR should be able to integrate seamlessly w/ other tools used by the organization. This can be done by adopting the same sort of language and frameworks as the organization. For example, having all of the security tools adopt the [MITRE ATT&CK](cybersecurity/resources/MITRE-ATT&CK.md) framework can make tool integration and detection/response processes much easier. Some common tools which EDRs should be able to integrate with include:
- SIM tools for threat detection
- SOAR tools for incident response
- and XDR tools (which combine the capabilities of the last 2)
#### Reporting
An EDR tool should be able to provide reporting to the organization. Reporting can include performance metrics such as mean time to respond to an incident, as well as compliance and regulatory reporting.

> [!Resources]
> - [CrowdStrike: EDR](https://www.crowdstrike.com/cybersecurity-101/endpoint-security/endpoint-detection-and-response-edr/)
> - [Wikipedia: EDR](https://en.wikipedia.org/wiki/Endpoint_detection_and_response)
> - [IBM Technology: What is EDR](https://www.youtube.com/watch?v=55GaIolVVqI)