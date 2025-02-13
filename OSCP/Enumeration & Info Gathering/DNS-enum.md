
# (Active) DNS Enumeration
[DNS](../../networking/DNS/DNS.md) is an important protocol and system for resolving [IP addresses](../../networking/OSI/3-network/IP-addresses.md) into domain names (check out my DNS notes for more). Each domain has *DNS records* attached to it which are publicly accessible and can give away some clues and info we can use in building a potential attack against it.
## Records
### NS Record
The [NS Record](../../networking/DNS/NS-record.md) contains the name of the *authoritative [name server](../../networking/DNS/DNS.md#Name%20Servers)* which hosts the most up to date and accurate information about the domain and which IP address it resolves to.
### A Record
The [A Record](../../networking/DNS/A-record.md) contains the IP address the domain or subdomain resolves to.
### AAAA Record
The AAAA record is just like an A record but is meant to be used for [IPv6](../../networking/OSI/3-network/IP-addresses.md#IPv6) addresses.
### MX Record
The [MX Record](../../networking/DNS/MX-record.md) contians the names of the servers which are responsible for handling [email](../../networking/email.md) which is sent to the domain. A domain can have more than one MX record.
### PTR Record
The [PTR Record](../../networking/DNS/PTR-record.md) is the *opposite* of an A record. Instead of storing the IP address that a domain resolves to, it stores *the domain an IP address resolves to*. Because of this, they're *not stored on a domain*. They are instead stored in the `in-addr.arpa` namespace of the `.arpa` [Top Level Domain](../../networking/DNS/DNS.md#Top%20Level%20Domain).
### CNAME
The [CNAME](../../networking/DNS/CNAME.md), or 'canonical name' record, stores the *alias* for a domain. In other words, it points to another domain name. CNAME records can *never* point to an IP address. They have to contain domains or subdomains. When a DNS server finds the CNAME record for a queried domain, it triggers a second lookup for the domain stored in the CNAME.
### TXT Record
The [TXT Record](../../networking/DNS/TXT-record.md) can contain any arbitrary data, human readable *AND machine readable*. Primarily, TXT records are used for domain verification and for storing [SPF](../../cybersecurity/defense/SPF.md) and [DMARC](../../cybersecurity/defense/DMARC.md) information. TXT records can be tasty during recon because they often tell us what technologies an organization may be using, and sometimes admins will use TXT records to store sensitive information.
## Enumeration Using Linux 
You can do DNS enumeration through automating common DNS tools like [dig](../../CLI-tools/dig.md). Using [bash](../../coding/languages/bash.md) we can automate DNS lookups by creating a list of common subdomain names and then using a for loop to loop over them, making DNS requests for each using dig.
### Bash Enum Example
This script will perform a type of DNS brute forcing to find valid subdomains for our target domain `megacorpone.com`. 
#### List: `list.txt`
```
www
ftp
mail
owa
proxy
dev
prod
test
sso
secure
```
#### Oneliner
For each word in our `list.txt` file, this bash oneliner will run the dig command and output the results for us in the terminal.
```bash
for ip in $(cat list.txt); do dig $ip.megacorpone.com; done
```
Output:
```bash
└# for ip in $(cat list.txt); do dig $ip.megacorpone.com; done
; <<>> DiG 9.10.6 <<>> www.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44885
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;www.megacorpone.com.		IN	A

;; ANSWER SECTION:
www.megacorpone.com.	300	IN	A	149.56.244.87

;; Query time: 108 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:42 PST 2025
;; MSG SIZE  rcvd: 64

; <<>> DiG 9.10.6 <<>> ftp.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 52785
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;ftp.megacorpone.com.		IN	A

;; AUTHORITY SECTION:
megacorpone.com.	300	IN	SOA	ns1.megacorpone.com. admin.megacorpone.com. 202102162 28800 7200 2419200 300

;; Query time: 154 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:43 PST 2025
;; MSG SIZE  rcvd: 94

; <<>> DiG 9.10.6 <<>> mail.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61648
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;mail.megacorpone.com.		IN	A

;; ANSWER SECTION:
mail.megacorpone.com.	300	IN	A	167.114.21.68

;; Query time: 111 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:43 PST 2025
;; MSG SIZE  rcvd: 65

; <<>> DiG 9.10.6 <<>> owa.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 19620
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;owa.megacorpone.com.		IN	A

;; AUTHORITY SECTION:
megacorpone.com.	300	IN	SOA	ns1.megacorpone.com. admin.megacorpone.com. 202102162 28800 7200 2419200 300

;; Query time: 103 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:43 PST 2025
;; MSG SIZE  rcvd: 94


; <<>> DiG 9.10.6 <<>> proxy.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 137
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;proxy.megacorpone.com.		IN	A

;; AUTHORITY SECTION:
megacorpone.com.	300	IN	SOA	ns1.megacorpone.com. admin.megacorpone.com. 202102162 28800 7200 2419200 300

;; Query time: 104 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:43 PST 2025
;; MSG SIZE  rcvd: 96

; <<>> DiG 9.10.6 <<>> dev.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 49398
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;dev.megacorpone.com.		IN	A

;; AUTHORITY SECTION:
megacorpone.com.	300	IN	SOA	ns1.megacorpone.com. admin.megacorpone.com. 202102162 28800 7200 2419200 300

;; Query time: 107 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:43 PST 2025
;; MSG SIZE  rcvd: 94

; <<>> DiG 9.10.6 <<>> prod.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 44055
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;prod.megacorpone.com.		IN	A

;; AUTHORITY SECTION:
megacorpone.com.	300	IN	SOA	ns1.megacorpone.com. admin.megacorpone.com. 202102162 28800 7200 2419200 300

;; Query time: 113 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:43 PST 2025
;; MSG SIZE  rcvd: 95

; <<>> DiG 9.10.6 <<>> test.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44496
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;test.megacorpone.com.		IN	A

;; ANSWER SECTION:
test.megacorpone.com.	300	IN	A	167.114.21.75

;; Query time: 103 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:43 PST 2025
;; MSG SIZE  rcvd: 65


; <<>> DiG 9.10.6 <<>> sso.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 21806
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;sso.megacorpone.com.		IN	A

;; AUTHORITY SECTION:
megacorpone.com.	300	IN	SOA	ns1.megacorpone.com. admin.megacorpone.com. 202102162 28800 7200 2419200 300

;; Query time: 101 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:44 PST 2025
;; MSG SIZE  rcvd: 94

; <<>> DiG 9.10.6 <<>> secure.megacorpone.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 23098
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4095
;; QUESTION SECTION:
;secure.megacorpone.com.		IN	A

;; AUTHORITY SECTION:
megacorpone.com.	300	IN	SOA	ns1.megacorpone.com. admin.megacorpone.com. 202102162 28800 7200 2419200 300

;; Query time: 113 msec
;; SERVER: 100.100.100.100#53(100.100.100.100)
;; WHEN: Thu Jan 23 15:16:44 PST 2025
;; MSG SIZE  rcvd: 97
```
### Cleaning it up
The output from the one-liner is nice, but it's messy and hard to read. We can clean it up by making an actual bash script. The script will clean things up by *not printing output* when there is no A record for queried domain, and *splitting* the results visually in the terminal for us (this is actually a script I wrote for myself when I first started doing external pen-tests. You can check out the repo [here](https://github.com/pentestpuppy/diglist)).
```bash
#!/bin/bash
# Made by TRASH PUPPY
#	2024

echo ""
echo -e "                    \033[32m :-- DNS RECORDS --:\033[0m"
echo ""

# Variable Declaration:
if [[ -z "$1" ]]; then
	echo ":-- Enter a file to use which containes new line separated IP addresses and/ or hostnames: "
	read -a file
else
	file=$1
fi

if [[ -z "$2" ]]; then
	echo ":-- Enter the root domain:"
	read -a root
else
	root=$2
fi

# Check for what type of record they want:
if [[ -z "$3" ]]; then
	echo ":-- What record type are you looking for? (ex: txt, all, a, n, aaaa): "
	read -a record
else
	record=$3
fi

echo -e ":-- Digging \033[32m$file\033[0m for \033[32m$record\033[0m record types..."
echo ""

for line in $(cat $file); do
	# If current item is not IP address format:
	if [[ $(echo $line | grep -E '([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}' -c) -eq 0 ]]; then
		# Does the current item already have tld format?
		if [[ $(echo $line | grep -E '[[:alnum:]]{2,}\.[[:alnum:]]{2,}' -c) -ne 0 ]]; then
			target=$line
		else
			target=$(echo $line\.$root)
		fi
	else
		target=$line
	fi

        echo -e "_________________________ \033[32m$target\033[0m _________________________"
	# Dig for domain name but check for results first:
	if [[ $(dig +short $target $record | wc -c) -eq 0 ]]; then
		echo -e ":--\033[31m NO RESULTS for $target\033[0m"
	else
		result=$(dig $target $record)
		echo -e ":--\033[32m RESULT:\033[0m $result" \
		&& sleep 0.1
	fi
done

echo ""
echo -e "                    \033[32m :-- DONE --:\033[0m"
```
#### Using Our Script
list.txt
```
www
ftp
mail
owa
proxy
router
```
output
```bash
└─# bash diglist.sh
                     :-- DNS RECORDS --:
:-- Enter a file to use which containes new line separated IP addresses and/ or hostnames:
list.txt
:-- Enter the root domain:
megacorpone.com
:-- What record type are you looking for? (ex: txt, all, a, n, aaaa):
a
:-- Digging list.txt for a record types...

_________________________ www.megacorpone.com _________________________
:-- RESULT:
; <<>> DiG 9.19.19-1-Debian <<>> www.megacorpone.com a
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58959
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.megacorpone.com.		IN	A

;; ANSWER SECTION:
www.megacorpone.com.	300	IN	A	149.56.244.87

;; Query time: 4 msec
;; SERVER: 172.31.0.2#53(172.31.0.2) (UDP)
;; WHEN: Thu Jan 23 20:26:52 EST 2025
;; MSG SIZE  rcvd: 64
_________________________ ftp.megacorpone.com _________________________
:-- NO RESULTS for ftp.megacorpone.com
_________________________ mail.megacorpone.com _________________________
:-- RESULT:
; <<>> DiG 9.19.19-1-Debian <<>> mail.megacorpone.com a
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19063
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;mail.megacorpone.com.		IN	A

;; ANSWER SECTION:
mail.megacorpone.com.	300	IN	A	167.114.21.68

;; Query time: 0 msec
;; SERVER: 172.31.0.2#53(172.31.0.2) (UDP)
;; WHEN: Thu Jan 23 20:26:52 EST 2025
;; MSG SIZE  rcvd: 65
_________________________ owa.megacorpone.com _________________________
:-- NO RESULTS for owa.megacorpone.com
_________________________ proxy.megacorpone.com _________________________
:-- NO RESULTS for proxy.megacorpone.com
_________________________ router.megacorpone.com _________________________
:-- RESULT:
; <<>> DiG 9.19.19-1-Debian <<>> router.megacorpone.com a
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56638
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;router.megacorpone.com.		IN	A

;; ANSWER SECTION:
router.megacorpone.com.	300	IN	A	167.114.21.70

;; Query time: 0 msec
;; SERVER: 172.31.0.2#53(172.31.0.2) (UDP)
;; WHEN: Thu Jan 23 20:26:52 EST 2025
;; MSG SIZE  rcvd: 67

                     :-- DONE --:
```
With our script bruteforcing the list for us, we discovered three subdomains which resolve to IP addresses: `www.megacorpone.com`, `mail.megacorpone.com`, and `router.megacorpone.com`. Two of these subdomains resolve to IP addresses which are likely in the *same [CIDR](../../networking/routing/CIDR.md) range*. 
### Reverse DNS Enumeration
Knowing that two of the subdomains likely share a CIDR range, we can infer that more hosts which are potentially related to the target have IP addresses within that range. We can brute force them using reverse DNS lookups and *PTR records* (if the domain admin configure PTR records for the domains). 
#### Oneliner
This bash one liner will do our reverse lookups using the dig command again. This time, our for loop needs to iterate through the entire CIDR range we think our target belongs to. The CIDR range is likely a */24* meaning it has 256 total addresses and 254 total hosts (since the first address is reserved for the network itself, and the 256th address is reserved as the *Broadcast address* for the network) within it. 

So, our one liner will have to iterate through all the IP addresses between `167.114.21.01` and `167.114.21.255`. We can achieve that by looping through a range. For each new IP address, we'll use the `dig` command w/ the `-x` flag to do a reverse lookup of the IP
```bash
for ip in $(seq 1 25); do printf "167.114.21.$ip "; dig +short -x 167.114.21.$ip  echo "\n"; done
```
### Other DNS Enum tools
#### [DNSEnum](https://www.kali.org/tools/dnsenum/)
```bash
└─# kali@kali:~$ dnsenum megacorpone.com
...
dnsenum VERSION:1.2.6

-----   megacorpone.com   -----

...

Brute forcing with /usr/share/dnsenum/dns.txt:
_______________________________________________

admin.megacorpone.com.                   5        IN    A        51.222.169.208
beta.megacorpone.com.                    5        IN    A        51.222.169.209
fs1.megacorpone.com.                     5        IN    A        51.222.169.210
intranet.megacorpone.com.                5        IN    A        51.222.169.211
mail.megacorpone.com.                    5        IN    A        51.222.169.212
mail2.megacorpone.com.                   5        IN    A        51.222.169.213
ns1.megacorpone.com.                     5        IN    A        51.79.37.18
ns2.megacorpone.com.                     5        IN    A        51.222.39.63
ns3.megacorpone.com.                     5        IN    A        66.70.207.180
router.megacorpone.com.                  5        IN    A        51.222.169.214
siem.megacorpone.com.                    5        IN    A        51.222.169.215
snmp.megacorpone.com.                    5        IN    A        51.222.169.216
syslog.megacorpone.com.                  5        IN    A        51.222.169.217
test.megacorpone.com.                    5        IN    A        51.222.169.219
vpn.megacorpone.com.                     5        IN    A        51.222.169.220
www.megacorpone.com.                     5        IN    A        149.56.244.87
www2.megacorpone.com.                    5        IN    A        149.56.244.87


megacorpone.com class C netranges:
___________________________________

 51.79.37.0/24
 51.222.39.0/24
 51.222.169.0/24
 66.70.207.0/24
 149.56.244.0/24


Performing reverse lookup on 1280 ip addresses:
________________________________________________

18.37.79.51.in-addr.arpa.                86400    IN    PTR      ns1.megacorpone.com.
...
```
#### [DNSRecon](https://github.com/darkoperator/dnsrecon)
```bash
└─# kali@kali:~$ dnsrecon -d megacorpone.com -t std
[*] std: Performing General Enumeration against: megacorpone.com...
[-] DNSSEC is not configured for megacorpone.com
[*] 	 SOA ns1.megacorpone.com 51.79.37.18
[*] 	 NS ns1.megacorpone.com 51.79.37.18
[*] 	 NS ns3.megacorpone.com 66.70.207.180
[*] 	 NS ns2.megacorpone.com 51.222.39.63
[*] 	 MX mail.megacorpone.com 51.222.169.212
[*] 	 MX spool.mail.gandi.net 217.70.178.1
[*] 	 MX fb.mail.gandi.net 217.70.178.217
[*] 	 MX fb.mail.gandi.net 217.70.178.216
[*] 	 MX fb.mail.gandi.net 217.70.178.215
[*] 	 MX mail2.megacorpone.com 51.222.169.213
[*] 	 TXT megacorpone.com Try Harder
[*] 	 TXT megacorpone.com google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA
[*] Enumerating SRV Records
[+] 0 Records Found
```
- `-d` signifies the domain name
- `-t` signifies the record type (`std` meaning 'standard' in this case)
##### Brute Forcing
You can also *Brute Force* domain names w/ `dnsrecon`:
```bash
└─# kali@kali:~$ dnsrecon -d megacorpone.com -D ~/list.txt -t brt
[*] Using the dictionary file: /home/kali/list.txt (provided by user)
[*] brt: Performing host and subdomain brute force against megacorpone.com...
[+] 	 A www.megacorpone.com 149.56.244.87
[+] 	 A mail.megacorpone.com 51.222.169.212
[+] 	 A router.megacorpone.com 51.222.169.214
[+] 3 Records Found
```
In this case `list.txt` is our list of subdomain prefixes from before.
## Enumeration Using Windows
### `nslookup`
`nslookup` is a command line tool on Windows computers which we can use to enumerate DNS. A basic command looks like this:
```cmd
C:\Users\student> nslookup mail.megacorptwo.com
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.50.151

Name:    mail.megacorptwo.com
Address:  192.168.50.154
```
The output tells us that `nslookup` queried the *default DNS server* at `192.168.50.151` to resolve the IP address for `mail.megacorptwo.com`. 
#### Querying for specific records
We can use `nslookup` to make our query more specifc. For example, to query for [TXT records](../../networking/DNS/TXT-record.md) , we can use the `-type=` flag.
```cmd
C:\Users\student>nslookup -type=TXT info.megacorptwo.com 192.168.50.151
Server:  UnKnown
Address:  192.168.50.151

info.megacorptwo.com    text =

        "greetings from the TXT record body"
```
#### Enumerating subdomains
You can also give `nslookup` a list (like we did before) to find subdomains of a domain. So, if `list.txt` is:
```
www
info
mail
```
We're going to need a [powershell](../../computers/windows/powershell.md) script for this unfortunately...
```powershell
# Define the domain and wordlist file
$domain = "megacorptwo.com"
$wordlist = "C:\student\list.txt"

# Read subdomains from the file
$subdomains = Get-Content $wordlist

# Loop through each subdomain and perform nslookup
foreach ($sub in $subdomains) {
    $fqdn = "$sub.$domain"
    $result = nslookup $fqdn 2>&1
    if ($result -match "Name:") {
        Write-Output "Found: $fqdn"
    }
}
```
If you wrote this script in Command Prompt like me (`copy con dnsenum.ps1`) then use this oneliner to run it using powershell from cmdprompt:
```powershell
C:\Users\student>powershell -ExecutionPolicy Bypass -File dnsenum.ps1
Found: mail.megacorptwo.com
Found: info.megacorptwo.com

C:\Users\student>
```

> [!Resources]
> - [DNSEnum](https://www.kali.org/tools/dnsenum/)
> - [DNSRecon](https://github.com/darkoperator/dnsrecon)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.