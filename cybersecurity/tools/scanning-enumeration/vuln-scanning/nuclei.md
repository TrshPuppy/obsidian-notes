
# Nuclei Vulnerability Scanner
[Nuclei](https://github.com/projectdiscovery/nuclei) is a CLI-based *EXPLOITABLE* vulnerability scanner. It works by 'sending requests across targets based on  a template'. It can scan across multiple protocols including [TCP](/networking/protocols/TCP.md), [DNS](/networking/DNS/DNS.md), [HTTP](www/HTTP.md), [SSL](/networking/protocols/SSL.md), [FTP](/networking/protocols/FTP.md), [WHOIS](/networking/protocols/whois.md), etc..
## Methodology
Nuclei uses [YAML](/coding/languages/YAML.md) files as templates to create and define methods for detecting and ranking security vulnerabilities on a target. Each template can be thought of as a *possible attack route*.
### Templates
Each YAML template *details a possible attack route* for a target. The template describes the vulnerability, its [severity](cybersecurity/resources/CVSS.md), priority, and associated exploits (if applicable). Templating allows Nuclei to supplement discovered vulnerabilities w/ potential threats and exploits.

Templates are downloaded onto your machine with nuclei and are kept in the nuclei install path in `/<nuclei root dir>/nuclei-templates`.  `cd`ing and listing everything in this directory will show  all the sub-directories of templates:
```bash
┌──(hakcypuppy㉿kali)-[~/nuclei/nuclei-templates]
└─$ ls
cnvd
cve
default-logins
... # etc
```

This is an example of the [nameserver-fingerprint template](https://github.com/projectdiscovery/nuclei-templates/blob/main/dns/nameserver-fingerprint.yaml):
```yaml
id: nameserver-fingerprint

info:
  name: NS Record Detection
  author: pdteam
  severity: info
  description: An NS record was detected. An NS record delegates a subdomain to a set of name servers.
  classification:
    cwe-id: CWE-200
  metadata:
    max-request: 1
  tags: dns,ns

dns:
  - name: "{{FQDN}}"
    type: NS
    matchers:
      - type: regex
        part: answer
        regex:
          - "IN\tNS\\t(.+)$"

    extractors:
      - type: regex
        group: 1
        regex:
          - "IN\tNS\t(.+)"

# digest: 4a0a0047304502201ea440eb1f3de07432e12f94f89b2db94a960b7e41bf0a985db8454471217852022100ea06c3b9f829f1e4cbdd3e2ce32b039e0cf6150525202a42361133fb321794fc:922c64590222798bb761d5b6d8e72950
```
#### Filters
Nuclei can filter templates based on three filter flags, each related to a filed in the template file:
##### `-tags`
Templates include *tag* fields which help specify the possible attack route. 
#### `-severity`
#### `-author`
### Workflows
Workflows are YAML files (saved in the `/nuclei/workflows` path) which *execute a sequence of templates*. Workflows allow users to run templates using defined conditions such as technology or target. For example, if your target includes Wordpress as a service, then the Wordpress workflow will be run (when Wordpress is detected).
#### Generic Workflows
Generic workflows are workflows which list a single or multiple templates to be executed. For example, here is a workflow which runs all the config-related templates:
```yaml
workflows:
  - template: files/git-config.yaml
  - template: files/svn-config.yaml
  - template: files/env-file.yaml
  - template: files/backup-files.yaml
```
#### Conditional Workflows
Conditional Workflows are executed *when a condition is matched* from a previous template. For example: this workflow will run all the Jira-related templates and if Jira is detected, it will then execute the *subtemplates* (which are jira exploits):
```yaml
workflows:
  - template: technologies/jira-detect.yaml
    subtemplates:
      - template: exploits/jira-exploit-1.yaml
      - template: exploits/jira-exploit-1.yaml
```
##### Matcher conditional
Conditional workflows can also execute subtemplates when the *matcher to a template is found in the results*:
```
workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: vbulletin
        subtemplates:
          - template: exploits/vbulletin-exp1.yaml
          - template: exploits/vbulletin-exp2.yaml
      - name: jboss
        subtemplates:
          - template: exploits/jboss-exp1.yaml
          - template: exploits/jboss-exp2.yaml
```
## Usage
Basic command:
```bash
nuclei -u https://target.com
```
### Specifying Targets:
#### `-u`: Target
Target URLs/ hosts to scan.
#### `-l`: Target List
Give Nuclei the path to a file containing a list of targets/ hosts.
```bash
nuclei -list hosts.txt
```
#### `-eh`: Exclude Hosts
A list of hosts to *exclude* from the scan.
#### `-sa`: Scan all IPs

### Executing Templates:
#### `-t`: Template
The `-t` flag is used to specify which template to execute. What `-t` actually does is *specifies the directory* where templates for a specific attack route are kept There are two ways to execute templates. You can either specify a template, or by using a *Workflow*.
##### Default
If `-t` is not given, Nuclei's *default* setting is to run *all the templates at the **template** installation path*.
##### Custom
```bash
# example of command w/ custom templates:
nuclei -u https://target.com -t cves/ -t exposures/
```
###### Custom GitHub Templates
To use a custom template from a GitHub repo, the repo should be *downloaded in the `github` directory*:
```bash
nuclei -u https://example.com -t github/repo-name
```
#### `-as`: Automatic Scan
Uses Wappalyzer (see [website-tech-recon](/nested-repos/PNPT-study-guide/PEH/recon/website-tech-recon.md)) to automatically scan based on technology found by Wappalyzer.
#### `-tl`: List templates
List all the available templates.
#### `-tc`: Template Condition
This flag can be used for *advanced filtering* of templates using complex expressions. The syntax can include logical operators (`||` and `&&`) and can be used with DSL helper functions (?).

For example, if you want to use templates whose id contains the keyword `xss` or whose tags contain `xss`, then your command would look like this:
```bash
nuclei -tc "contains(id,'xss') || contains(tags,'xss')" -u target.com
```
##### Supported Fields for Template Condition flag (`-tc`):
- `id` string
- `name` string
- `description` string
- `tags` slice of strings
- `authors` slice of strings
- `severity` string
- `protocol` string
- `http_method` slice of strings
- `body` string (containing all request bodies if any)
- `matcher_type` slice of string
- `extractor_type` slice of string
- `description` string
### Output
#### `-o`: Output
Give Nuclei a file to write the output to.
```bash
nuclei -u https://target.com -o output.txt
```
#### `-s`: Silent
Only output successful findings.
#### `-ts`: Timestamp
Add timestamps to the output
#### Output Formats:
- `-ms`:  Give a path to a markdown file for output to be written to.
- `-j` `-jsonl`: Write output JSONL(ines) format.
### Other Possible Fields to Use:
- Configurations
- Interactsh
- Fuzzing
- Uncover
- Rate-Limit
- Optimizations
- Headless
- Debug
- Update
- Statistics
- Cloud
### Environment Variables
You can also use environment variables w/ Nuclei. For example the `MARKDOWN_EXPORT_SORT_MODE` variable allows you to run Nuclei w/ 'sorted Markdown outputs':
```bash
MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclie_report/
```

> [!Resources]
> - [Nuclei Repo](https://github.com/projectdiscovery/nuclei)
> - [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei/overview)
> - [Nuclei Template Guide](https://nuclei.mintlify.app/template-guide/variables)
> - [Nuclei: Workflows](https://c4pr1c3.github.io/nuclei-docs/templating-guide/workflows.html)
> - My [other notes](https://github.com/TrshPuppy/obsidian-notes) (linked throughout) can all be found here.