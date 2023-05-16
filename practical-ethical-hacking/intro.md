
# Practical Ethical Hacking Intro:

## Course Requirements/ Pre-reqs:
1. [ ] Basic IT knowledge
2. [ ] Mid Course Capstone: 12BG RAM
3. [ ] Wireless Hacking: wireless adapter with monitor mode
4. [ ] Active Directory lab build: 16GB RAM

## Day in the Life:
### External Network Pentest:
Most common type performed, assessing and testing an organization's security from the outside, usually from a remote location. This type of pentest is *most common* because compliance organizations require external network pentests annually.

They also tend to be cheaper than other types of pentesting. This makes it easier for companies to start adopting pentesting as a practice for their security.

#### Methodology:
Focuses heavily on [OSINT](nested-repos/PNPT-study-guide/OSINT-fundamentals/OSINT-overview.md), gathering open-source information on the company and its employees. Usually takes ~32-40 hours + 8-16 for report writing.

##### OSINT:
What data can be gathered (which is public) to aid breaking in/ exploiting the organization's network and gaining access to restricted spaces/ information?

*Vulnerability Scanning:* external network endpoints are scanned by bots all the time. The likelihood of finding a vulnerability through passive scanning is relatively low. Most companies have enough protections in place to cover this aspect of their security with patching etc.

Instead, OSINT is focused on *gathering intel* such as what is the topology of the network? Where are the login panels? Who are the users?

### Internal Network Pentest:
Assessing the security of an organization's from *inside the network*. The network has already been breached and/or part of the agreement w/ the client is to allow a laptop/ device to be brought internally and attached to the network (which the pentester can then remote into to perform the assessment).

#### Methodology:
Focuses heavily on [Active Directory](nested-repos/PNPT-study-guide/practical-ethical-hacking/active-directory/active-directory-overview.md) attacks. A majority of organizations use Active Directory in the technical environments, so it's critical to understand in order to perform internal pentests.

Usually last 32-40 hours w/ another 8-16 hours for writing the report.

### Web Application Pentest:
Can be considered an *external* pentest. Usually sought out by a company in order to fulfill compliance, test the vulnerability/ security of the app before launch, or because it's been requested by stakeholders of the app.

#### Methodology:
Focused on web-based attacks and testing guidelines dictated by [OWASP](https://owasp.org/). Knowing OWASP's [Top 10](https://owasp.org/www-project-top-ten/) most critical security to web apps is important for performing web app pentesting.

Usually lasts *at least 40 hours* in order to cover a thorough checklist of what needs to be tested against the web app. 8-16 hours for report writing.

### Wireless Pentest
Assessing the organization's wireless security specifically.

#### Methodology:
The methodology changes depending on the type of wireless being used. Different types include guest networks, WPA2-PSK vs WPA2 Enterprise. Also includes brute-forcing passwords for wi-fi.

>	Example: to pentest a guest wireless network, we probably want to assess the *segmentation* of the network (i.e. is it kept separate from the employee wi-fi, etc.).

Requires a *wireless network adapter* which is compatible with your pentesting machine.

### Physical Pentest:
Assessing an organization's physical security and end-user training. Can include things like testing badge security, building surveillance, whether restricted resources are properly barricaded, etc.

#### Methodology:
Depends on the task at hand and the client's goals. Some organizations just want to see if you can get into the building, or to a sensitive part of the building such as a network closet. Some engagements require social engineering.

Usually takes 16-40 hours depending on the task, w/ 4-8 hours for report writing.

##### Social Engineering:
Social engineering is using manipulation to gain access to or gather restricted information on a target. A common example of a social engineering tactic is [phishing](/cybersecurity/attacks/phishing.md).
