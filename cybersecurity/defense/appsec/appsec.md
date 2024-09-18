
# Application Security (AppSec)
AppSec is a discipline w/i cybersecurity which address the security of software and applications throughout the entire software development lifecycle (SDLC). It deals w/ both prevention and mitigation of vulnerabilities.
## SDLC
AppSec takes into consideration bugs and vulnerabilities introduced to an application *throughout its SDLC* (software development lifecycle). According to [IBM](https://www.youtube.com/watch?v=nthEXs12nFE) most bugs and vulns are introduced *during the production* of an application. HOWEVER, they're usually not discovered until *much later*.

This means that the *cost of defects in the code* is much higher later through the application's development.
### Traditional SDLC
Traditionally, software is built in the following phases:
1. Design phase
2. Coding/ development phase
3. Testing phase
4. Release phase (production)
In this traditional model there is a clear divide b/w development and operations (i.e. developers vs operations team-members). The  problem w/ this is that, in some organizations especially, the divide b/w development and operations is harsh & un-budging.

This lends to an *'over the wall'* mentality, i.e. we write the software and then we send it 'over the wall' to operations and stop caring about it. Additionally, *security isn't introduced until the code is in production.*
### Modern SDLC/ DevOps
DevOps is a more modern implementation of the SDLC which attempts to *integrate dev and operations* in a way which is cyclical and much more intertwined. However, this model still *does not integrate security.*
### DevSecOps
DevSecOps is very similar to DevOps. It basically just integrates security into *every part of the SDLC*, so that security it considered earlier and more often. The mentality here is commonly referred to as "a shift left" mentality. That's because it's *shifting the consideration of security to earlier phases of the SDLC*.

DevSecOps embraces *security by design*. It emphasizes *collaboration* b/w developers, operations, and security. It also attempts to use *automation* wherever it can to make the process more efficient.
## Secure Coding
In order to integrate secure coding into the SDLC, some needs need to be met:
- Coding Practices checklist: procedures for how to handle/ mitigate vulnerabilities etc.
	- [OWASP](cybersecurity/resources/OWASP.md)
- Trusted Libraries: have an in depth list of third party software being used. So if a vuln is released in one of them, it's easy to track it down and take care of it
	- ex: [log4j](../../vulnerabilities/log4j.md)
- Standard architecture: spell out in advance how the system should look for taking certain approcahces
	- application security architecture
- mistakes to avoid:
	- OWASP top 10: what are the current top 10 vulns?
- Software bill of materials (SBOM)
	- where did all of the components come from
		- libs
		- dependencies
		- versions
		- origin of all components
		- vulnerabilities
	- makes it much easier to respond to vulns which occur in these components and where to make changes
	- recover much faster
## Vulnerability Testing Tools:
Testing for vulnerabilities in the code should be started as early as possible in the SDLC and continue throughout. SAST and DAST (described below) should *both be used* (not a matter of choosing one over the other).
### SAST
**Static Application Security Testing**: SAST tools analyze *source code and compiled binaries* of code to help find flaws and vulnerabilities. This type of application analysis is considered *white box* testing because the analysis is done on the code itself w/ no limits or unknowns (the tester has access to all the code, frameworks, etc.).

SAST is normally done *as early as possible* in the SDLC and usually takes place in the development environment of an application. It's usually taken on by the developers of the application using their own testing tools.
#### Shift to the left
A "shift to the left" is a phrase in AppSec which refers to integrating application security *earlier in the SDLC*. Traditionally, security of an application isn't considered *until just before release into production* which is disadvantageous for a few reasons. One reason is that any flaws which are found are difficult to address b/c there typically is not enough time left before release to address them.
### DAST
**Dynamic Application Security Testing:** tools analyze an application *at runtime* to find flaws and vulnerabilities. This type of analysis is considered *black box* because the application is already running and compiled and the tester *has no access to the source code, frameworks, etc.* Any flaws which are found are essentially found 'by accident' since the tester isn't analyzing the source code which allows for those flaws directly.
### Software Composition Analysis (SCA)
SCA tools analyze the risk and vulnerabilities introduced to an application *by third party and/or open source* components. SCA tools typically work by creating a list of third-party components in the codebase and keep track of any vulnerabilities, licensing issues, CVEs, etc.. 

Without SCA tools, it can be difficult for an organization to find and keep track of third-party software in their code environment, as well as the flaws and vulnerabilities they introduce to the application.
### IAST
**Interactive Application Security Testing**: IAST tools help secure applications by collecting data which can be used by a security team to analyze real-time events. These tools are normally *automated* and *run as agents* in the environment to collect monitoring data.

> [!Resources]
> - [IBM: Cybersecurity Architecture: AppSec](https://www.youtube.com/watch?v=nthEXs12nFE)
> - [GuidePoint Security: Application Security](https://www.guidepointsecurity.com/education-center/application-security/)
> - [Nicole Choi (blog post): The architecture of SAST tools](https://github.blog/2024-02-12-the-architecture-of-sast-tools-an-explainer-for-developers/)
> - [Synopsis: SAST vs DAST](https://www.synopsys.com/blogs/software-security/sast-vs-dast-difference.html)

