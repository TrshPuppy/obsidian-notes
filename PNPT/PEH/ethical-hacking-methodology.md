
# Ethical Hacking Methodology
There are 5 stages when conducting pen-testing/ ethical hacking:
## 1. Reconnaissance
Gathering information about the target through passive means like OSINT, DNS records, browsing websites, etc.. The goal is to *gather as much info as impossible* on the target so that you can plan and effective test.
## 2. Scanning
Scanning is like reconnaissance but more active because you are *potentially leaving traces of your presence.* This stage includes probing a system/ network to discover features about it which can be used to gain access.

Effective scanning will tell you about:
- open ports
- services running on the system/ network
- vulnerabilities in those services

Scanning includes techniques like port scanning, vulnerability scanning, network mapping, etc..
## 3. Gaining Access
Using the information gathered during recon and scanning, vulnerabilities in the target system are used to gain access. Some techniques used during this stage are password brute forcing, social engineering, exploiting vulnerabilities in software, etc..
## 4. Maintaining Access
Once the target has been penetrated, you have to maintain access by concealing your tracks, establishing "back doors" so you can re-access if necessary, and gaining persistence.

In ethical hacking this stage is focused on mimicking what a true hacker would do to find out how much damage can potentially be done and what is at risk for the target.
## 5. Covering Tracks
Once the exploitation and exfiltration of the system is complete, you need to cover your tracks and remove and evidence of your presence. Some techniques covering your tracks include deleting logs, removing or changing files, and attempting to restore the system to its original state.

The goal is to try to make sure your activities go and stay undetected,