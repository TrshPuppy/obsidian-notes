
# Custom Word List Generator (CeWL)
CeWL is a CLI tool which will spider a website and generate *a custom wordlist* based on keywords it finds in the [HTML](/coding/markup/HTML.md). The most common use case is to develop a wordlist *which can be used in a password cracking or brute forcing tool* such as [john](../../../cracking/tools/john.md) or [hydra](../../../cracking/tools/hydra.md).

The advantage of CeWL is that the wordlist it generates *is specific to the target* since a lot of passwords and usernames are a combination of keywords related to the business/ service.
## Usage
### Installation
CeWL can be downloaded from [this repository](https://github.com/digininja/CeWL) but requires some additional dependencies.
### Options
```bash
./cewl.rb

CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
Usage: cewl [OPTIONS] ... <url>

    OPTIONS:
	-h, --help: Show help.
	-k, --keep: Keep the downloaded file.
	-d <x>,--depth <x>: Depth to spider to, default 2.
	-m, --min_word_length: Minimum word length, default 3.
	-o, --offsite: Let the spider visit other sites.
	-w, --write: Write the output to the file.
	-u, --ua <agent>: User agent to send.
	-n, --no-words: Don\'t output the wordlist.
	-a, --meta: include meta data.
	--meta_file file: Output file for meta data.
	-e, --email: Include email addresses.
	--email_file <file>: Output file for email addresses.
	--meta-temp-dir <dir>: The temporary directory used by 
				exiftool when parsing files, default /tmp.
	-c, --count: Show the count for each word found.
	-v, --verbose: Verbose.
	--debug: Extra debug information.

	Authentication
	--auth_type: Digest or basic.
	--auth_user: Authentication username.
	--auth_pass: Authentication password.

	Proxy Support
	--proxy_host: Proxy host.
	--proxy_port: Proxy port, default 8080.
	--proxy_username: Username for proxy, if required.
	--proxy_password: Password for proxy, if required.

	Headers
	--header, -H: In format name:value - can pass multiple.

    <url>: The site to spider.
```
## Syntax
### Basic Syntax
```bash
cewl http://<target IP> -w <output file>
```
### `-w` wordlist
This is essentially the output file where the generated wordlist will go.
### `-d` depth
The `-d`/ depth flag *tells cewl whether or not it should follow links and collect words from the pages they link to*. For example, giving cewl a depth of `2` will tell it to follow links on the target page, grab words from the linked pages, but *NOT* follow the links on those pages.
```bash
cewl http://10.10.161.7 -d 2 -w wordlist.txt
```
**NOTE:** Cewl *WILL NOT* follow links to third-party/ offsite websites (see `--offsite`).
### `-m` & `-x` min/ max
The `-m` flag tells cewl the *minimum word length* and `-x` tells it the *max word length*.

For example, if the target's password policy states that password must be at least 7 characters, but less than 15, then our command would look like:
```bash
cewl http://10.10.161.7 -d 1 -m 7 -x 15 -w wordlist.txt
```
### `-ua` user agent
Set your User Agent string when making the request for the webpage.
### `-e` email
Include email addresses found in the search (this is meant for *creating an email list*). If you use this flag, you should also provide a filename for the output file:
```bash
cewl http://10.10.161.7 -d emails.txt -w wordlist.txt
```
### `--offsite`
This will tell cewl that it's allowed to follow external links and spider words from there.

> [!Resources]
> - [Try Hack Me Advent of Cyber '23](https://tryhackme.com/room/adventofcyber2023)
> - [Digi.ninja: CeWL](https://digi.ninja/projects/cewl.php#usage)




