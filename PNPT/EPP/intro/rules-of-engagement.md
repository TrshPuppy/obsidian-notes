
# Pen-test Rules of Engagement
The ROE is a document which outlines what you can and cannot do throughout the engagement and is signed and agreed upon by you *and the client*. It also defines *roles and responsibilities* for members of both parties.
## Sections:
The following list of sections may or may not be present on an ROE document. Each company has a different way of doing the ROE, although there are sections which should absolutely be included such as the scope, disclosure, and acceptance.

ROEs will also differ per engagement depending on what the client wants in their assessment.
### Objective
A general blurb which outlines the intent of the ROE document. A sentence which might go here could be:
> The intent of this document is to outline and clearly define the roles and responsibilities of all parties, and the agreed-upon details of the assessment.
### Applicability
Describes what the document specifically applies to, i.e. the document likely applies to 'all elements involved in the assessment' offered by the pen-testing party to the client. This also includes relevant contacts w/i the client's organization
### Roles & Responsibilities
This section outlines the roles and responsibilities for all parties involved in the assessment. Some examples of common roles outlined here are:
#### The Penetration Testing Team
This section should include all members making up the pen-testing team for the engagement *including team members from the client* who will be involved.
#### The Client
This section will outline the responsibilities of the client. Some examples of responsibilities could include:
- observing and documenting intrusion attempts made by offensive team members (you)
- preventing the involvement of law enforcement
- ensuring the engagement is kept secret/ is unannounced to employees

This section may also define specific roles for members of the client team such as:
##### Customer Point of Contact (CPOC)
Responsible for coordinating w/ the pen-testing team & should be able to verify suspicious activity and differentiate it from coincidental real-world hacking attempts. Should also be able to re-schedule activities if needed.

The CPOC will stay in-contact with the pen-testing POC (the pen-testing team's point of contact) to ensure clear, on-going communication throughout the engagement.
- CPOC name: Fake Name
- CPOC Email: fake.email@customer.com
#### The Pen-testing Team
Like the client section, this section will include all the team members making up the attacking/ assessment team and outline their roles and responsibilities. This section may include a blurb about each team member's coverage under a non-disclosure agreement. Some example responsibilities here could be:
- documenting all pen-testing activities
- documenting success and failures
##### Pen-testing team's POC
This section will talk about the responsibilities of the pen-testing team's POC. These responsibilities will likely include:
- coordinating b/w the client and pen-testing team
- scheduling pen-testing activities including cancellations and re-scheduling
- making their contact information available to the CPOC
- etc.
### Rules of Engagement
This section will be more specific including dates and times of activities, scope, disclosure etc.. Some possible sub-sections include:
#### Time and date of assessment
May include prohibited times/dates (such as after hours/weekends)
#### Announcement
A blurb covering how the client will announce or not announce the test to other employees. May also include a description of what the pen team should do if they discover a previously/ maliciously compromised asset during the test.
#### Discloser
A blurb about whether the client has excluded specific assets from the test like IP addresses and hostnames.
#### Status Updates
when and how often regular communication will be made regarding the overall status of the engagement,
#### Test method specifics
The ROE should include sections specific to the test, such as what type of pentest is being done, etc.. The following are some example sections: 
##### External Pentest (or whatever type)
What is in scope or out of scope regarding the client's external network. This could include IP addresses, domains, CIDRs etc..
##### Malware Emulation Testing
Outlines which systems will be tested for malware detection and response. Should also include *specific* tools to be used during the engagement, for example: Meterpreter, Cobalt Strike, etc..

This section may also include a blurb regarding the client's responsibility to communicate to the team if they detect malware activity so the finding can be confirmed b/w both teams.
##### Keeping Access
A blurb describing that a team may use certain techniques to maintain access to a network during the duration of the engagement.
#### Bounds of the test
A blurb re-enforcing that all IP addresses/ other assets included in the *assessment waiver* will be scanned for vulnerabilities. Should also include what will happen to assets which are *found coincidentally* during the engagement but not outlined in the waiver (likely they won't be included in the scanning/ testing but noted that they were discovered).
#### Out of Scope
A list of items/ assets which are out of scope for the assessment. This includes IP addresses, hostnames, etc. as well as techniques such as social engineering, DDoS, etc..
#### Stop Point
A blurb about the exact stop point (time and date) for the engagement.
#### Project Closure
Different from the stop point. This time and date refers to when the entire relationship b/w both parties ends, i.e. the engagement has been done and the pen team has delivered their findings and debriefed the client.
#### Post Mortem
Describes the responsibility of the pen team to deliver a post mortem to the client. The post mortem should report and explain all attacks and their findings to the client.
#### Disclaimer
This section describes the 'assumptions and limitations of liability' that the client is agreeing to. For example, this section might include a list like this:
> The client agrees to the following assumptions and limitations of liability as necessary for the engagement:
> - the pen-testing team may use commercial or common tools to perform the test
> - the client understands that the actions taken by the pen-testing team mirror or emulate real-world malicious hacking activities
> - the client understands that some of these activities may impede system performance, crash production systems, and permit unapproved access
> - the client understands that the actions taken by the pen-testing team may involve risks which *are unknown* or unforeseen by both parties
#### Acceptance
This section is likely the last blurb and basically states that by signing the document, the undersigned asserts that they are authorized to enter the agreement/ waiver on behalf of the client. 

This section also grants permission to the pen-testing team to exercise the test as described by the document and states that the client accepts all of provisions set forth by it.

**NOTE:** If this document is not signed *the test should not begin and cannot be started* (you could be sued).

> [!Resources]
> - [TCM Security](https://tcm-sec.com/)