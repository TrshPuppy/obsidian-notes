
# Common Legal Pen-Testing Documents
In general, this is the process:
## Sales
Client reaches out requesting pen-testing services. First, the client usually requests you sign an NDA so you don't share information you learn about their platform in the process.

The the two parties sit down to a "sales meeting" in which 2 documents are put together:
- Master Service Agreement
- Statement of Work
### Mutual Non-Disclosure (NDA)
Both parties agree to not take anything learned throughout the process and disclose it to third parties.
### Master Service Agreement (MSA)
Contractual Document which specifies the objectives of the engagement and outline the responsibilities of both parties. Blanket agreement that covers multiple contracts.
#### [Rapid7](https://www.rapid7.com) Example Agreement
Rapid7 has their [Master Service Agreement](https://www.rapid7.com/legal/msa/) available for view.
### Statement of Work (SOW)
Specific to a single contract. Covers activities, deliverables, timelines, and quote for payment. Basically "this is the type of test we're going to do. This is when we're going to finish it by. We're going to supply you with a report, and this is how much money the whole engagement will cost".
### Additional Sales Documents:
#### Sample Report
Some clients like to see a sample reports
#### Recommendation Letters
Some client like to see recommendations from other businesses/ clients before taking you on.
## Rules of Engagement (before the test)
Once the SOW, NDA, MSA etc. are all signed and agreed upon, you and the client will have a *Rules of Engagement Meeting*. Before this (in the Sales stage), you and the client likely agreed upon general scope and terms. This meeting will *cover specifics* of your testing.

**YOU CANNOT START THE ASSESSMENT UNTIL THIS DOCUMENT IS SIGNED**
### Scope
This document will list specific *IP Addresses* (mostly) which you can and *cannot attack*. Most commonly, clients will not want you to perform system-interrupting/ breaking things such as [denial of service](cybersecurity/TTPs/exploitation/denial-of-service.md) or anything which will *take down or interrupt their live/ production settings and services.*

Some clients will not allow you to do [social-engineering](cybersecurity/TTPs/delivery/social-engineering.md), mostly because they prefer it as a *separate assessment*.
## Findings Report (after test)
In general the [findings report](cybersecurity/pen-testing/report-writing.md) is a write-up, in detail, of all of your findings while doing the pentest.

> [!Resources]
> - [TCM Security](https://tcm-sec.com/)
> - [Rapid7: MSA](https://www.rapid7.com/legal/msa/)

> [!My previous notes (linked in text)]
> - You'll find them all [here](https://github.com/TrshPuppy/obsidian-notes)


