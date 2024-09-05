
# Subfinder
## Awk
```bash
cat subfinder_out.json| jq | awk '/"host"/ {print}' | cut -d '│Nmap done: 1067 IP addresses (1067 hosts up) scanned in 98161.08 seconds
"' -f 4 > subfinder_subdomains.txt
```

```code
24-09-03 10:35 172.31.146.214 subfinder # subfinder -d geha.com -all -stats -o subfinder_out.json -oJ

               __    _____           __
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/

                projectdiscovery.io

[INF] Current subfinder version v2.6.6 (latest)
[INF] Loading provider config from /root/.config/subfinder/provider-config.yaml
[INF] Enumerating subdomains for geha.com
{"host":"design.geha.com","input":"geha.com","source":"leakix"}
{"host":"facwebstg1-2.geha.com","input":"geha.com","source":"chaos"}
{"host":"rimtestapp02.geha.com","input":"geha.com","source":"chaos"}
{"host":"rimtestweb02.geha.com","input":"geha.com","source":"chaos"}
{"host":"faccfg1-1.geha.com","input":"geha.com","source":"chaos"}
{"host":"lxgehapubapptst.geha.com","input":"geha.com","source":"chaos"}
{"host":"mail.geha.com","input":"geha.com","source":"chaos"}
{"host":"lsfi.geha.com","input":"geha.com","source":"digitorus"}
{"host":"entscwebtest02.geha.com","input":"geha.com","source":"chaos"}
{"host":"facwebdev1-1.geha.com","input":"geha.com","source":"chaos"}
{"host":"lscrtstweb01.geha.com","input":"geha.com","source":"chaos"}
{"host":"www.star.geha.com","input":"geha.com","source":"chaos"}
{"host":"cloud.info.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"lsspeedtest.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"test-citrix.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"careers.geha.com","input":"geha.com","source":"chaos"}
{"host":"facwsltst1-2.geha.com","input":"geha.com","source":"chaos"}
{"host":"facwebprd1.geha.com","input":"geha.com","source":"chaos"}
{"host":"omp.news.geha.com","input":"geha.com","source":"chaos"}
{"host":"nfuseiis.geha.com","input":"geha.com","source":"waybackarchive"}
{"host":"smtp03.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"facwebprd1-3.geha.com","input":"geha.com","source":"chaos"}
{"host":"labbigip02.geha.com","input":"geha.com","source":"chaos"}
{"host":"lxtestspweb03.geha.com","input":"geha.com","source":"chaos"}
{"host":"webmail.geha.com","input":"geha.com","source":"crtsh"}
{"host":"secureftptest.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"lyncedge.geha.com","input":"geha.com","source":"chaos"}
{"host":"rimprdapp02.geha.com","input":"geha.com","source":"chaos"}
{"host":"facwebtst1-2.geha.com","input":"geha.com","source":"chaos"}
{"host":"facwsldev1-1.geha.com","input":"geha.com","source":"chaos"}
{"host":"ns3.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"facwebstg1-1.geha.com","input":"geha.com","source":"chaos"}
{"host":"go.geha.com","input":"geha.com","source":"chaos"}
{"host":"ns4.geha.com","input":"geha.com","source":"chaos"}
{"host":"cdnetwork-test.geha.com","input":"geha.com","source":"alienvault"}
{"host":"www.keypath.geha.com","input":"geha.com","source":"chaos"}
{"host":"member-portal.geha.com","input":"geha.com","source":"waybackarchive"}
{"host":"webaccounts.geha.com","input":"geha.com","source":"sitedossier"}
{"host":"lb.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"feedback.geha.com","input":"geha.com","source":"leakix"}
{"host":"gehaapi-mgm-dev.geha.com","input":"geha.com","source":"leakix"}
{"host":"gehaapi-mgm-tst.geha.com","input":"geha.com","source":"chaos"}
{"host":"citrix.geha.com","input":"geha.com","source":"chaos"}
{"host":"lssftptest01.geha.com","input":"geha.com","source":"chaos"}
{"host":"lxentsprap01.geha.com","input":"geha.com","source":"chaos"}
{"host":"rimprdweb01.geha.com","input":"geha.com","source":"chaos"}
{"host":"view.info.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"m.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"gehamail03.geha.com","input":"geha.com","source":"chaos"}
{"host":"stage-webaccounts.geha.com","input":"geha.com","source":"chaos"}
{"host":"click.info.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"internal.geha.com","input":"geha.com","source":"chaos"}
{"host":"ctxag2.geha.com","input":"geha.com","source":"chaos"}
{"host":"news.geha.com","input":"geha.com","source":"chaos"}
{"host":"secureftp1.geha.com","input":"geha.com","source":"alienvault"}
{"host":"geha.com","input":"geha.com","source":"digitorus"}
{"host":"securemail.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"guestwireless.geha.com","input":"geha.com","source":"chaos"}
{"host":"veracoretst1-1.geha.com","input":"geha.com","source":"chaos"}
{"host":"medicalsc-test.geha.com","input":"geha.com","source":"waybackarchive"}
{"host":"livechat.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"mobileiron.geha.com","input":"geha.com","source":"chaos"}
{"host":"rimprdweb02.geha.com","input":"geha.com","source":"chaos"}
{"host":"login.geha.com","input":"geha.com","source":"waybackarchive"}
{"host":"rimtestapp01.geha.com","input":"geha.com","source":"chaos"}
{"host":"cryptolx.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"facwebprd1-2.geha.com","input":"geha.com","source":"chaos"}
{"host":"facwebtst1-1.geha.com","input":"geha.com","source":"chaos"}
{"host":"gehaapi-mgm-prd.geha.com","input":"geha.com","source":"chaos"}
{"host":"lsgehapubappstg.geha.com","input":"geha.com","source":"chaos"}
{"host":"keypath.geha.com","input":"geha.com","source":"chaos"}
{"host":"medical-test.geha.com","input":"geha.com","source":"chaos"}
{"host":"healthbalance.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"facapptrn1.geha.com","input":"geha.com","source":"chaos"}
{"host":"lxcrtstweb01.geha.com","input":"geha.com","source":"chaos"}
{"host":"ctxag.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"ctxag3.geha.com","input":"geha.com","source":"chaos"}
{"host":"labbigip01.geha.com","input":"geha.com","source":"chaos"}
{"host":"lxfi.geha.com","input":"geha.com","source":"chaos"}
{"host":"erstx.geha.com","input":"geha.com","source":"waybackarchive"}
{"host":"ns2.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"facwsltst1-1.geha.com","input":"geha.com","source":"chaos"}
{"host":"ns1.geha.com","input":"geha.com","source":"chaos"}
{"host":"securemembermessaging.geha.com","input":"geha.com","source":"waybackarchive"}
{"host":"tools.geha.com","input":"geha.com","source":"waybackarchive"}
{"host":"mta.info.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"image.info.geha.com","input":"geha.com","source":"leakix"}
{"host":"test.member-portal.geha.com","input":"geha.com","source":"chaos"}
{"host":"gehaapi-mgm-stg.geha.com","input":"geha.com","source":"chaos"}
{"host":"labbigip02b.geha.com","input":"geha.com","source":"chaos"}
{"host":"apim.geha.com","input":"geha.com","source":"chaos"}
{"host":"stage.member-portal.geha.com","input":"geha.com","source":"chaos"}
{"host":"star.geha.com","input":"geha.com","source":"chaos"}
{"host":"identity.geha.com","input":"geha.com","source":"waybackarchive"}
{"host":"lsforcegwcluster-wcg.geha.com","input":"geha.com","source":"alienvault"}
{"host":"info.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"lxspeedtest.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"smtp02.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"facwsldev1-2.geha.com","input":"geha.com","source":"chaos"}
{"host":"sip.geha.com","input":"geha.com","source":"chaos"}
{"host":"gehaweb-prd.internal.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"securemessaging.geha.com","input":"geha.com","source":"alienvault"}
{"host":"lxmisentry01.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"ebooks.geha.com","input":"geha.com","source":"leakix"}
{"host":"faccmuprd1.geha.com","input":"geha.com","source":"chaos"}
{"host":"facwebdev1-2.geha.com","input":"geha.com","source":"chaos"}
{"host":"log.geha.com","input":"geha.com","source":"chaos"}
{"host":"apim.internal.geha.com","input":"geha.com","source":"chaos"}
{"host":"scm.internal.geha.com","input":"geha.com","source":"chaos"}
{"host":"scm.geha.com","input":"geha.com","source":"chaos"}
{"host":"eft.geha.com","input":"geha.com","source":"waybackarchive"}
{"host":"smtp01.geha.com","input":"geha.com","source":"hackertarget"}
{"host":"crypto.geha.com","input":"geha.com","source":"chaos"}
{"host":"lxdevspweb04.geha.com","input":"geha.com","source":"chaos"}
{"host":"rimtestweb01.geha.com","input":"geha.com","source":"chaos"}
{"host":"www.geha.com","input":"geha.com","source":"sitedossier"}
{"host":"gehamail01.geha.com","input":"geha.com","source":"chaos"}
{"host":"lxgehapubappstg.geha.com","input":"geha.com","source":"chaos"}
{"host":"rimprdapp01.geha.com","input":"geha.com","source":"chaos"}
{"host":"sc.geha.com","input":"geha.com","source":"chaos"}
{"host":"share.geha.com","input":"geha.com","source":"alienvault"}
[INF] Found 121 subdomains for geha.com in 26 seconds 788 milliseconds
[INF] Printing source statistics for geha.com

 Source               Duration      Results     Errors
────────────────────────────────────────────────────────
 alienvault           5.083s              5          0
 anubis               56ms                0          1
 builtwith            0s                  0          0
 chaos                718ms              74          0
 commoncrawl          26.782s         -1152          0
 crtsh                5.491s              1          1
 digitorus            121ms               2          0
 dnsdb                0s                  0          0
 dnsdumpster          42ms                0          1
 hackertarget         261ms              23          0
 leakix               447ms               5          0
 netlas               470ms               0          1
 rapiddns             943ms               0          0
 sitedossier          59ms               -2          0
 virustotal           0s                  0          0
 waybackarchive       3.289s              9          0


 The following sources were included but skipped...

 bevigil
 binaryedge
 bufferover
 c99
 censys
 certspotter
 chinaz
 dnsrepo
 facebook
 fofa
 fullhunt
 github
 hunter
 intelx
 passivetotal
 quake
 redhuntlabs
 robtex
 securitytrails
 shodan
 threatbook
 whoisxmlapi
 zoomeyeapi


24-09-03 10:35 172.31.146.214 subfinder # ls
subfinder_out.json
24-09-03 10:36 172.31.146.214 subfinder # cat subfinder_out.json| jq
{
  "host": "ctxag2.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "news.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "secureftp1.geha.com",
  "input": "geha.com",
  "source": "alienvault"
}
{
  "host": "click.info.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "internal.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "guestwireless.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "veracoretst1-1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "medicalsc-test.geha.com",
  "input": "geha.com",
  "source": "waybackarchive"
}
{
  "host": "geha.com",
  "input": "geha.com",
  "source": "digitorus"
}
{
  "host": "securemail.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "rimprdweb02.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "login.geha.com",
  "input": "geha.com",
  "source": "waybackarchive"
}
{
  "host": "livechat.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "mobileiron.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "facwebtst1-1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "gehaapi-mgm-prd.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lsgehapubappstg.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "rimtestapp01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "cryptolx.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "facwebprd1-2.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "keypath.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "medical-test.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lxcrtstweb01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "healthbalance.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "facapptrn1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "labbigip01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lxfi.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "erstx.geha.com",
  "input": "geha.com",
  "source": "waybackarchive"
}
{
  "host": "ctxag.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "ctxag3.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "ns1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "securemembermessaging.geha.com",
  "input": "geha.com",
  "source": "waybackarchive"
}
{
  "host": "tools.geha.com",
  "input": "geha.com",
  "source": "waybackarchive"
}
{
  "host": "ns2.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "facwsltst1-1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "test.member-portal.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "mta.info.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "image.info.geha.com",
  "input": "geha.com",
  "source": "leakix"
}
{
  "host": "gehaapi-mgm-stg.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "labbigip02b.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "star.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "identity.geha.com",
  "input": "geha.com",
  "source": "waybackarchive"
}
{
  "host": "apim.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "stage.member-portal.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lsforcegwcluster-wcg.geha.com",
  "input": "geha.com",
  "source": "alienvault"
}
{
  "host": "smtp02.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "facwsldev1-2.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "sip.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "info.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "lxspeedtest.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "gehaweb-prd.internal.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "faccmuprd1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "facwebdev1-2.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "log.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "securemessaging.geha.com",
  "input": "geha.com",
  "source": "alienvault"
}
{
  "host": "lxmisentry01.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "ebooks.geha.com",
  "input": "geha.com",
  "source": "leakix"
}
{
  "host": "scm.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "eft.geha.com",
  "input": "geha.com",
  "source": "waybackarchive"
}
{
  "host": "apim.internal.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "scm.internal.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lxdevspweb04.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "rimtestweb01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "smtp01.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "crypto.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "www.geha.com",
  "input": "geha.com",
  "source": "sitedossier"
}
{
  "host": "gehamail01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "sc.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "share.geha.com",
  "input": "geha.com",
  "source": "alienvault"
}
{
  "host": "lxgehapubappstg.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "rimprdapp01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "rimtestapp02.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "rimtestweb02.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "design.geha.com",
  "input": "geha.com",
  "source": "leakix"
}
{
  "host": "facwebstg1-2.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "mail.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "faccfg1-1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lxgehapubapptst.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "facwebdev1-1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lscrtstweb01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "www.star.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lsfi.geha.com",
  "input": "geha.com",
  "source": "digitorus"
}
{
  "host": "entscwebtest02.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "test-citrix.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "careers.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "facwsltst1-2.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "cloud.info.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "lsspeedtest.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "nfuseiis.geha.com",
  "input": "geha.com",
  "source": "waybackarchive"
}
{
  "host": "facwebprd1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "omp.news.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "labbigip02.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lxtestspweb03.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "webmail.geha.com",
  "input": "geha.com",
  "source": "crtsh"
}
{
  "host": "smtp03.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "facwebprd1-3.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "rimprdapp02.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "secureftptest.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "lyncedge.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "facwebtst1-2.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "facwsldev1-1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "go.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "ns4.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "cdnetwork-test.geha.com",
  "input": "geha.com",
  "source": "alienvault"
}
{
  "host": "ns3.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "facwebstg1-1.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "feedback.geha.com",
  "input": "geha.com",
  "source": "leakix"
}
{
  "host": "gehaapi-mgm-dev.geha.com",
  "input": "geha.com",
  "source": "leakix"
}
{
  "host": "gehaapi-mgm-tst.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "www.keypath.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "member-portal.geha.com",
  "input": "geha.com",
  "source": "waybackarchive"
}
{
  "host": "webaccounts.geha.com",
  "input": "geha.com",
  "source": "sitedossier"
}
{
  "host": "lb.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "lxentsprap01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "rimprdweb01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "citrix.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "lssftptest01.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "gehamail03.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "stage-webaccounts.geha.com",
  "input": "geha.com",
  "source": "chaos"
}
{
  "host": "view.info.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}
{
  "host": "m.geha.com",
  "input": "geha.com",
  "source": "hackertarget"
}


#!/bin/bash
file=$(cat subfinder_out.json)

for row in $file; do
	host=$(echo $row | cut -d ")
```