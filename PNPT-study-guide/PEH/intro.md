
# Practical Ethical Hacking Intro:

## Types of Pentests:
### External Network Pentest
Most common type performed, assessing and testing an organization's security from the outside, usually from a remote location. This type of pentest is *most common* because compliance organizations require external network pentests annually.

They also tend to be cheaper than other types of pentesting. This makes it easier for companies to start adopting pentesting as a practice for their security.
#### Methodology
Focuses heavily on [OSINT](/cybersecurity/TTPs/recon/OSINT.md), gathering open-source information on the company and its employees. Usually takes ~32-40 hours + 8-16 for report writing.
##### OSINT
What data can be gathered (which is public) to aid breaking in/ exploiting the organization's network and gaining access to restricted spaces/ information?

*Vulnerability Scanning:* external network endpoints are scanned by bots all the time. The likelihood of finding a vulnerability through passive scanning is relatively low. Most companies have enough protections in place to cover this aspect of their security with patching etc.

Instead, OSINT is focused on *gathering intel* such as what is the topology of the network? Where are the login panels? Who are the users?
### Internal Network Pentest
Assessing the security of an organization's from *inside the network*. The network has already been breached and/or part of the agreement w/ the client is to allow a laptop/ device to be brought internally and attached to the network (which the pentester can then remote into to perform the assessment).
#### Methodology
Focuses heavily on [Active Directory](/PNPT/PEH/active-directory/active-directory-overview.md) attacks. A majority of organizations use Active Directory in the technical environments, so it's critical to understand in order to perform internal pentests.

Usually last 32-40 hours w/ another 8-16 hours for writing the report.
### Web Application Pentest
Can be considered an *external* pentest. Usually sought out by a company in order to fulfill compliance, test the vulnerability/ security of the app before launch, or because it's been requested by stakeholders of the app.
#### Methodology
Focused on web-based attacks and testing guidelines dictated by [OWASP](https://owasp.org/). Knowing OWASP's [Top 10](https://owasp.org/www-project-top-ten/) most critical security to web apps is important for performing web app pentesting.

Usually lasts *at least 40 hours* in order to cover a thorough checklist of what needs to be tested against the web app. 8-16 hours for report writing.
### Wireless Pentest
Assessing the organization's wireless security specifically.
#### Methodology
The methodology changes depending on the type of wireless being used. Different types include guest networks, WPA2-PSK vs WPA2 Enterprise. Also includes brute-forcing passwords for wi-fi.

>	Example: to pentest a guest wireless network, we probably want to assess the *segmentation* of the network (i.e. is it kept separate from the employee wi-fi, etc.).

Requires a *wireless network adapter* which is compatible with your pentesting machine.
### Physical Pentest
Assessing an organization's physical security and end-user training. Can include things like testing badge security, building surveillance, whether restricted resources are properly barricaded, etc.
#### Methodology
Depends on the task at hand and the client's goals. Some organizations just want to see if you can get into the building, or to a sensitive part of the building such as a network closet. Some engagements require social engineering.

Usually takes 16-40 hours depending on the task, w/ 4-8 hours for report writing.
##### Social Engineering
*The weakest element in an organization's security is the human element*!

Social engineering is using manipulation to gain access to or gather restricted information on a target. A common example of a social engineering tactic is [phishing](/cybersecurity/attacks/phishing.md).

Social engineering and physical pentesting tend to go hand in hand. 
### Other Assessments:
#### Mobile Pentest
Basically web-app pentesting but on a mobile app. Each operating system comes with its own pentesting techniques (Android, iOS, etc.).
#### IoT Pentest
Usually involves IoT devices which have wireless capabilities but are not traditional user-interfaced computers like laptops/ desktops/ mobile phones, etc.
#### Red Team Engagement
When an organization asks for a pentest but not for details regarding when or how. Methodology can include anything defined in the scope or the engagement.
#### Purple Team Engagement
When a Red Team and Blue Team run an engagement together to determine a baseline for the current security/ detection measures. I.E. the red team may attempt an attack and the Blue Team will report on how the network/ target changed or didn't change (including detection measures, network traffic, etc.).

Not commonly requested by organizations who are newer to pentesting engagements.
### Report Writing
Successful consultants need to be able to write professional reports which can be understood by both technical and non-technical audiences. Usually delivered w/i a week of the engagement.
#### Executive Summary
The portion of the report catered to a non-technical audience. Should be *crystal clear* when communicating what issues were found and how to fix them.
#### Technical Findings Section
For people in the organization who are responsible for technical work including devs, IT personnel, security engineer, etc.. This section should include descriptions of the tools used on the engagement as well as *high-level* recommendations *and technical recommendations*.
#### Debrief
Designed to walk technical and non-technical audiences through your findings during the engagement (may be presented in front of technical and non-technical people alike).

You should be prepared to give a technical *and* high-level explanation of your findings.

The Debrief also allows the client to ask questions about or challenge your findings before a final report is written (the initial report is always a *draft*).

> [!Resources]
> - [OWASP Top 10](https://owasp.org/www-project-top-ten/)

> [!My previous notes (linked in the text)]
> - [phishing](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/TTPs/phishing.md)
> - [OSINT](https://github.com/TrshPuppy/obsidian-notes/tree/main/cybersecurity/TTPs/recon/OSINT.md)




