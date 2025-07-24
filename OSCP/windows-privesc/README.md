---
aliases:
  - Windows privesc
---
# Windows PrivEsc Techniques
This file really is just here to make it easier to link Windows Privesc throughout the rest of the notes in this repo/vault. But since you're here, here is a table of contents I guess
## TOC
- Overview of Windows Security Mechanisms
	- [access-tokens](security-mechanisms/access-tokens.md)
	- [MIC](security-mechanisms/MIC.md)
	- [SID](security-mechanisms/SID.md)s
	- [UAC](security-mechanisms/UAC.md)
- [Enumerating for Privesc Opportunities](enumeration/enumeration.md)
	- [automated techniques](enumeration/automated-enum.md)
	- [powershell-logging](enumeration/powershell-logging.md)
	- Finding [sensitive-files](enumeration/sensitive-files.md)
- Exploiting Windows Services for Privesc
	- [Windows Services](windows-services/README.md) Overview
	- [Service Binary Hijacking](windows-services/hijacking-service-binaries.md)
	- [PowerUp.ps1](windows-services/powerUp-ps1.md)
	- [DLL Hijacking](windows-services/DLL-hijacking.md)