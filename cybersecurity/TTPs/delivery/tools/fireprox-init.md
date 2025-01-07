
# Fireprox
Init.

Fireprox is a command line tool which uses an aws config file (with API key and secret) to spin up passthrough [proxies](../../../../networking/design-structure/proxy.md) which rotated the source IP address with every request they make. You can use it to avoid being *blocked* by a target when making many requests. 
## Use
You can use fireprox to create a proxy URL. This proxy URL will pass all of the traffic you send to it to the *destination/ target server* which you configure it to send to. Fireprox will then *return the target server's responses* back to you.
### Creating a Proxy instance:
```bash
python3 fire.py --access_key '<AWS access key>' \
--secret_access_key '<secret AWS access key>' --region 'us-east-1' \
--command create \
--url '<target Server>'
```
### Listing instances
```bash
python3 fire.py --access_key '<AWS access key>' \
--secret_access_key '<secret AWS access key>' --region 'us-east-1' \
--command list

(<api id>) fireprox_microsoftonline: https://<REDACT>.execute-api.us-east-1.amazonaws.com/fireprox/ => https://login.microsoftonline.com/
(<api id>) fireprox_microsoft: https://<REDACT>.execute-api.us-east-1.amazonaws.com/fireprox/ => https://login.microsoft.com/
...
```
### Updating a proxy instance:
If you want to change the target url, you can update a fireprox instance like this:
```bash
python3 fire.py --access_key '<AWS access key>' \
--secret_access_key '<secret AWS access key>' --region 'us-east-1' \
--command update --api_id <the id of the current instance> \
--url <new target url>
```
### Deleting an instance:
```bash
python3 fire.py --access_key '<AWS access key>' \
--secret_access_key '<secret AWS access key>' --region 'us-east-1' \
--command delete \
--api_id <the id of the current instance>
```

> [!Resources]
> - [GitHub](https://github.com/ustayready/fireprox)