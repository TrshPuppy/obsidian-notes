
# (PASSIVE) Google Dorking/ Hacking
Popularized by Johnny Long's 2001 book ["Google Hacking"](https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Long.pdf).  Google Dorking is the process of finding information on a target through the use of crafted Google search engine queries. Queries can be further sharpened through the use of *operators* which help to narrow down or filter results.
## Operators
### Modifying operators
Operators can be modified with `-` to *exclude* them from the results. For example, if I want to search for the site megacorpone.com but want to exclude all of the [HTML](../../cybersecurity/bug-bounties/hackerone/hacker101/HTML.md) files from the results:
```bash
site:megacorpone.com -ext:html
```
### `site:`
The `site` operator limits results to a specific domain. For example, the following query (Google search) returns only results from `github.com`:
```bash
site:github.com password
```
### `filetype:`/  `ext:`
These two operators filter results to only whos specific filetypes or extensions.
```bash
site:github.com ext:log
```
### `intitle:`
This operator returns pages which have the specified string in their title. For example, you can use this to find directory listings on a target domain:
```bash
intitle:"index of" site:megacorpone.com
```
## Resources
### Google Hacking Database
[Google Hacking Database](https://www.exploit-db.com/google-hacking-database) is a database hosted by [Exploit DB](../../cybersecurity/TTPs/exploitation/tools/exploit-db.md) of tasty Google Dorks other people have discovered. Peruse it to find some you may want to use.
### [DorkSearch](https://dorksearch.com/)
Provides a subset of pre-built quieies and a tool to build queries for searches. 

> [!Resources]
> - [Blackhat: Google Hacking for Pentesters](https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Long.pdf)
> - [Google: Refining Google Searches](https://support.google.com/websearch/answer/2466433?hl=en)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
> - [DorkSearch](https://dorksearch.com/)

> [!Related]
> - [google-fu](../../PNPT/PEH/recon/google-fu.md) (PNPT notes)

