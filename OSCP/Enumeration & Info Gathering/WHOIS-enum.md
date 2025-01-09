
# [WHOIS](../../networking/protocols/whois.md) Enumeration
WHOIS is a [TCP](../../networking/protocols/TCP.md) network protocol and database which provides information about [DNS](../../networking/DNS/DNS.md) domain names. WHOIS information is largely related to the domain's [Name Servers](../../networking/DNS/DNS.md#Name%20Servers) and registration information. All of this information is public but some registrars provide private registration for a fee (which obfuscates information about the person/ company who registered the domain).
## Tools
### [`whois`](../../CLI-tools/whois.md)
`whois` is a linux commandline tool which you can use to query name servers for information on a domain name. 
```bash
whois megacorpone.com -h 192.168.50.251
.. SNIP ..

   Domain Name: MEGACORPONE.COM
   Registry Domain ID: 1775445745_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.gandi.net
   Registrar URL: http://www.gandi.net
   Updated Date: 2024-12-22T21:09:21Z
   Creation Date: 2013-01-22T23:01:00Z
   Registry Expiry Date: 2026-01-22T23:01:00Z
   Registrar: Gandi SAS
   Registrar IANA ID: 81
   Registrar Abuse Contact Email: abuse@support.gandi.net
   Registrar Abuse Contact Phone: +33.170377661
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: NS1.MEGACORPONE.COM
   Name Server: NS2.MEGACORPONE.COM
   Name Server: NS3.MEGACORPONE.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2025-01-08T22:01:48Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

.. SNIP ..

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.
Domain Name: megacorpone.com
Registry Domain ID: 1775445745_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.gandi.net
Registrar URL: http://www.gandi.net
Updated Date: 2024-12-22T21:09:21Z
Creation Date: 2013-01-22T22:01:00Z
Registrar Registration Expiration Date: 2026-01-22T23:01:00Z
Registrar: GANDI SAS
Registrar IANA ID: 81
Registrar Abuse Contact Email: abuse@support.gandi.net
Registrar Abuse Contact Phone: +33.170377661
Reseller:
Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited
Registry Registrant ID:
Registrant Name: Alan Grofield
Registrant Organization: MegaCorpOne
Registrant Street: 2 Old Mill St
Registrant City: Rachel
Registrant State/Province: Nevada
Registrant Postal Code: 89001
Registrant Country: US
Registrant Phone: +1.9038836342
Registrant Phone Ext:
Registrant Fax:
Registrant Fax Ext:
Registrant Email: 3310f82fb4a8f79ee9a6bfe8d672d87e-1696395@contact.gandi.net
Registry Admin ID:
Admin Name: Alan Grofield
Admin Organization: MegaCorpOne
Admin Street: 2 Old Mill St
Admin City: Rachel
Admin State/Province: Nevada
Admin Postal Code: 89001
Admin Country: US
Admin Phone: +1.9038836342
Admin Phone Ext:
Admin Fax:
Admin Fax Ext:
Admin Email: 3310f82fb4a8f79ee9a6bfe8d672d87e-1696395@contact.gandi.net
Registry Tech ID:
Tech Name: Alan Grofield
Tech Organization: MegaCorpOne
Tech Street: 2 Old Mill St
Tech City: Rachel
Tech State/Province: Nevada
Tech Postal Code: 89001
Tech Country: US
Tech Phone: +1.9038836342
Tech Phone Ext:
Tech Fax:
Tech Fax Ext:
Tech Email: 3310f82fb4a8f79ee9a6bfe8d672d87e-1696395@contact.gandi.net
Name Server: NS1.MEGACORPONE.COM
Name Server: NS2.MEGACORPONE.COM
Name Server: NS3.MEGACORPONE.COM

.. SNIP ..
```
In this example, we're using `whois` to query the name server on our local network (using the `-h` flag) for information on the domain `megacorpone.com`.

In the output, some interesting pieces of info we may be able to use later are:
- the nameservers for `megacorpone.com`: `NS1.MEGACORPONE.COM`, `NS2.MEGACORPONE.COM`, and `NS3.MEGACORPONE.COM`
- the person listed as "Alan Grofield" in the `Tech Name` field
#### Reverse WHOIS
If we give `whois` an [IP address](../../networking/OSI/3-network/IP-addresses.md) then we can perform a *reverse WHOIS lookup* to discover more information
 ```bash
┌──(trshpuppy㉿kali)-[~/oscp/recon]
└─$ whois 38.100.193.70
.. SNIP ..

NetRange:       38.0.0.0 - 38.255.255.255
CIDR:           38.0.0.0/8
NetName:        COGENT-A
NetHandle:      NET-38-0-0-0-1
Parent:          ()
NetType:        Direct Allocation
OriginAS:       AS174
Organization:   PSINet, Inc. (PSI)
RegDate:        1991-04-16
Updated:        2023-10-11
Comment:        IP allocations within 38.0.0.0/8 are used for Cogent customer static IP assignments.
Comment:
Comment:        Reassignment information for this block can be found at rwhois.cogentco.com 4321
Comment:
Comment:        Geofeed https://geofeed.cogentco.com/geofeed.csv
Ref:            https://rdap.arin.net/registry/ip/38.0.0.0

OrgName:        PSINet, Inc.
OrgId:          PSI
Address:        2450 N Street NW
City:           Washington
StateProv:      DC
PostalCode:     20037
Country:        US
RegDate:
Updated:        2023-10-11
Comment:        Geofeed https://geofeed.cogentco.com/geofeed.csv
Ref:            https://rdap.arin.net/registry/entity/PSI

ReferralServer:  rwhois://rwhois.cogentco.com:4321

OrgAbuseHandle: COGEN-ARIN
OrgAbuseName:   Cogent Abuse
OrgAbusePhone:  +1-877-875-4311
OrgAbuseEmail:  abuse@cogentco.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/COGEN-ARIN

OrgNOCHandle: ZC108-ARIN
OrgNOCName:   Cogent Communications
OrgNOCPhone:  +1-877-875-4311
OrgNOCEmail:  noc@cogentco.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/ZC108-ARIN

OrgTechHandle: IPALL-ARIN
OrgTechName:   IP Allocation
OrgTechPhone:  +1-877-875-4311
OrgTechEmail:  ipalloc@cogentco.com
OrgTechRef:    https://rdap.arin.net/registry/entity/IPALL-ARIN

RTechHandle: PSI-NISC-ARIN
RTechName:   IP Allocation
RTechPhone:  +1-877-875-4311
RTechEmail:  ipalloc@cogentco.com
RTechRef:    https://rdap.arin.net/registry/entity/PSI-NISC-ARIN

.. SNIP ..

Found a referral to rwhois.cogentco.com:4321.

%rwhois V-1.5:0010b0:00 rwhois.cogentco.com (CGNT rwhoisd 1.2.0)
network:ID:NET4-2664C10018
network:Network-Name:NET4-2664C10018
network:IP-Network:38.100.193.0/24
network:Org-Name:Biznesshosting, Inc.
network:Street-Address:500 GREEN ROAD
network:City:POMPANO BEACH
network:State:FL
network:Country:US
network:Postal-Code:33064
network:Tech-Contact:ZC108-ARIN
network:Updated:2024-05-13 18:48:33
%ok
```
The results from the reverse lookup tells us *who is hosting the IP address*. 
### [`curL`](../../CLI-tools/linux/remote/curL.md)
If `whois` is not available on your machine, you can also use [curL](../../CLI-tools/linux/remote/curL.md) to make the same query. For this, we need to send a [telnet](../../networking/protocols/telnet.md) request to the American Registry for Internet Numbers ([ARIN](https://www.arin.net/)), which is one of the internet numbers authorities who manage and adminster IP addresses.
```bash
┌─[25-01-09 6:57:03]:(rose.pineau@)-[~/Documents/repos/obsidian-notes]
└# echo '38.100.193.70' | curl telnet://whois.arin.net:43
.. SNIP ..

#
# Query terms are ambiguous.  The query is assumed to be:
#     "n 38.100.193.70"
#
# Use "?" to get help.
#

NetRange:       38.0.0.0 - 38.255.255.255
CIDR:           38.0.0.0/8
NetName:        COGENT-A
NetHandle:      NET-38-0-0-0-1
Parent:          ()
NetType:        Direct Allocation
OriginAS:       AS174
Organization:   PSINet, Inc. (PSI)
RegDate:        1991-04-16
Updated:        2023-10-11
Comment:        IP allocations within 38.0.0.0/8 are used for Cogent customer static IP assignments.
Comment:
Comment:        Reassignment information for this block can be found at rwhois.cogentco.com 4321
Comment:
Comment:        Geofeed https://geofeed.cogentco.com/geofeed.csv
Ref:            https://rdap.arin.net/registry/ip/38.0.0.0

OrgName:        PSINet, Inc.
OrgId:          PSI
Address:        2450 N Street NW
City:           Washington
StateProv:      DC
PostalCode:     20037
Country:        US
RegDate:
Updated:        2023-10-11
Comment:        Geofeed https://geofeed.cogentco.com/geofeed.csv
Ref:            https://rdap.arin.net/registry/entity/PSI

ReferralServer:  rwhois://rwhois.cogentco.com:4321

OrgTechHandle: IPALL-ARIN
OrgTechName:   IP Allocation
OrgTechPhone:  +1-877-875-4311
OrgTechEmail:  ipalloc@cogentco.com
OrgTechRef:    https://rdap.arin.net/registry/entity/IPALL-ARIN

OrgNOCHandle: ZC108-ARIN
OrgNOCName:   Cogent Communications
OrgNOCPhone:  +1-877-875-4311
OrgNOCEmail:  noc@cogentco.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/ZC108-ARIN

OrgAbuseHandle: COGEN-ARIN
OrgAbuseName:   Cogent Abuse
OrgAbusePhone:  +1-877-875-4311
OrgAbuseEmail:  abuse@cogentco.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/COGEN-ARIN

RTechHandle: PSI-NISC-ARIN
RTechName:   IP Allocation
RTechPhone:  +1-877-875-4311
RTechEmail:  ipalloc@cogentco.com
RTechRef:    https://rdap.arin.net/registry/entity/PSI-NISC-ARIN
```

> [!Resources]
> - [ARIN](https://www.arin.net/)
