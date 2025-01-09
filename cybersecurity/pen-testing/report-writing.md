
# Writing a Penetration Testing Report
After completing a professional penetration test for a client, a report is written which details the activity and the technical security risks of the client's infrastructure which were identified during it.

Pen-test reports include the client's security posture, vulnerabilities, concerns ranked by priority, and suggested fixes. Not only is it used by the client to improve their security, it's also used to *maintain regulatory compliance*. The report is also *proof* that the company takes security seriously enough to have hired experts to test it.

Clients can use the report to help them:
- budget for hiring or affording resources for their security team
- provision security training for their employees
- invest in new defensive tools/ practices

Penetration testers can use the report to:
- cover their ass in case of hostility from client staff
- make a good impression on clients to ensure repeat customers
- encourage 
## Note taking:
Note taking should follow the same/ similar process every time. This will make notes more organized for reference later and will help organize your pen-testing process.
1. Make a template
2. Have a checklist/ playbook for ea. engagement
3. Automate tedious parts such as timestamping or logging the shell. 
### Important elements to track:
During the engagement, keeping an eye on the following will help you compile the report afterwards
- Admin info
- Scope
- Targets
- ROE (Rules of Engagement)
- Attack paths
- Found or cracked credentials
- Findings
- Vulnerability scans & research
- Service enumeration
- Web info
- Active Directory info
- OSINT
- Logs
- Activity
- Artifacts
- Cleanup
## Overall Objectives
The pentest report is meant to answer the following questions:
- How was the issue found?
- What is the *root cause* of the vulnerabilities
- How *difficult was it* to take advantage of these vulnerabilities?
- Is it possible to use the vulnerability *for further access and exploitation?*
- What is *impact on the client?*
- How can found issues *be fixed or mitigated?*
## Sections
The following sections are included in almost all reports. Some reports will have others which go beyond this:
### Executive Summary:
The executive summary will almost always be *the only thing that client executives will read*. It should be a general, high-level overview of the engagement, and should focus on the *impacts* and *significant risks* to their business, critical systems, clients, and data.

Can be up to 2 pages, anything more will probably be overlooked so keeping it *concise* is important. This part should be written *assuming the reader is non-technical* & for an audience who is *making decisions on how to allocate funding* based on the report's findings.

This section should include:
- summary of what was done
- where the client's defenses excelled or were proficient
- where defenses failed to stop you as the attacker
- recommendations for remediation (should be *vendor agnostic*)
### Recommendations or Remediations:
This section should provide the client w/ recommendations for the short, medium, and long terms. It should start by addressing the *most critical flaws first*, then high and medium. If there are low priority findings and/ or a lot of findings, they can be *included in an attached appendix.*

The best way to report the severity of findings + recommended fixes is to *use a scoring system* & classification set. The [CVSS](cybersecurity/resources/CVSS.md) (Common Vulnerability Scoring System) and [CVEs](cybersecurity/resources/CVEs.md).

This section can also be organized *based on findings* like this:
```txt
- Short Term
	- Finding 2: Set strong password requirements on all accounts
	- Finding 5: Change default Admin credentials of <service>
	- Finding 7: ...
- Medium Term
	- Finding 1: Disable LLMNR wherever possible
	- Finding 2: Enhance domain password policy
	- finding 3: ...
	- ...
- Long Term
	- Perform ongoing network vulnerability assessments and audits
	- Perform periodic Active Directory security assessments
	- ...
```

To increase the validity of your recommendations it's good to supplement this section *with external/ third party links and resources*. Including these will lend to your credibility.
### Technical Findings:
In this section you will provide the *technical details* of your findings. This section can be *as long as you need* in order to explain the path you took  and the actions it required.

This section should be as detailed as possible b/c it's *meant for the people who will be fixing the issues* based on your findings. Be descriptive and specific.
#### Your Methodology
This should be included throughout this section. You should explain your thought process, why you took certain actions, and how they progressed.
#### Objectives
This section defines and explains your objective. It's important communicate your mission clearly because the people reading may not have been aware of the engagement (and may not even know you exploited them).
#### Scope
Document the original, agreed upon scope, including IP addresses, horsts, domains, etc.. This is so the team reading your report can understand *exactly which of their assets were being tested*.
#### Details
This section is where you detail how you completed your tasks and/or overall mission and objective. It should include both how you were able to bypass defenses, and *when their defenses were able to rebuff you.*
### Appendix:
This section will hold any supporting details including screenshots, output results from tools like [nmap](../../CLI-tools/linux/remote/nmap.md), credentials you discovered or cracked, and other documentation required to *prove your actions*. They can either be included as attachments, or directly in the report.

*The more you can provide to prove your findings, the better.*

> [!Resources]
> - [HTB: Penetration testing reports](https://www.hackthebox.com/blog/penetration-testing-reports-template-and-guide)