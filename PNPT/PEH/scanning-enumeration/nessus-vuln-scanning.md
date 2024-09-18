
# Vulnerability Scanning w/ Nessus
[Nessus](../../../cybersecurity/TTPs/recon/tools/vuln-scanning/nessus.md) is a vulnerability scanner used commonly in penetration testing. 
## Installation
Download the tool from `https://www.tenable.com/downloads/nessus?loginAttempted=true`. Use `dpkg -i Nessus...` in the `/Downloads` folder to install. When you install the tool, follow the prompts in the terminal, you'll need an activation code for *Nessus Essentials*:
```bash
Unpacking Nessus Scanner Core Components...

 - You can start Nessus Scanner by typing /bin/systemctl start nessusd.service
 - Then go to https://kali:8834/ to configure your scanner

┌──(hakcypuppy㉿kali)-[~/Downloads]
└─$ /bin/systemctl start nessusd.service   
```
Follow the link to `https://kali:8834/`:![](/PNPT/PNPT-pics/nessus-1.png)

## Basic Network Scan
Let's scan [Kioptrix](/PNPT/PEH/scanning-enumeration/kioptrix.md). In the basic network scan under `General` create a target called 'Kioptrix' w/ the IP address.
### Schedule
Allows you to schedule scans of a target.
### Notifications
Via an [SMTP](/networking/protocols/SMTP.md) server which you have to set up/ configure/ provide to Nessus.
### Discovery
Discovery is the important tab in Nessus for us. This allows you to configure how you want to scan. You can either choose to scan all ports, common ports, or specific/ custom port ranges.
### Assessment
Assessment is another important tab. This tab allows you to configure what type of vulnerabilities Nessus will scan for on the target(s). Nessus *is limited to web-based vulnerabilities.*

Scanning for known will take less time than scanning for "complex".
### Report
This tab allows you to configure how Nessus will report back the information it gathers.
### Advanced
This can be kept to 'default' but this tab allows you to change how Nessus scans each host etc.
## Advanced Scans
Advanced scans allow more granular control over how the scans are carried out against targets.
### Pinging a Host
Under the Discovery -> Host Discovery tabs you can choose whether Nessus pings each host and which protocols it uses to ensure the target is online. It also allows you to choose whether you want to scan 'fragile' devices such as network printers.
### Assessment
In the Assessment tab you can configure *brute forcing*, web app scanning, Windows-specific scanning techniques, malware scanning, and the used of detected SIDs against databases.
### Credentials
The Credentials tab (horizontal) allows you to add credentials you may have for targets. This will make the scan 'deeper' since Nessus can use the credentials on targets to access new surfaces.
## Launching a Scan
Once you've set all your scan settings, you can launch the scan from its listing in your Folder section.
### Vulnerabilities
By clicking on the currently scanning scan, you can see what vulnerabilities are being found including their severity and other details for each target.
![](/PNPT/PNPT-pics/nessus-2.png)

![](/PNPT/PNPT-pics/nessus-3.png)

## Scan Results
Once the scan has finished, we can go through the findings starting w/ the most severe. Based on how many results there are, we can tell Kioptrix is super vulnerable
### Example: OpenSSL Unsupported
Clicking on this finding we can see more details:
![](/PNPT/PNPT-pics/nessus-4.png)

At the bottom we can see the installed version is out of date. This should be added to our findings.
### Reporting Nessus Findings
To report Nessus findings specifically, we can export the findings into a Nessus file which can later be converted into an excel document, etc.. this can be added to our [report](/cybersecurity/pen-testing/report-writing.md).

> [!Resources]
> - [Tenable: Nessus Downloads](https://www.tenable.com/downloads/nessus?loginAttempted=true)

> [!My previous notes (linked in text)]
> - [SMTP](https://github.com/TrshPuppy/obsidian-notes/tree/main/networking/protocols/SMTP.md)
> - [report](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/pen-testing/report-writing.md)

