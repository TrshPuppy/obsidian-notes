
# WPScan
## Usage
### Quick Start
```bash
gem install wpscan
```
### Config file
`.wpscan/scan.yaml`
```yaml
cli_options:
	api_key: ''
	verbose: true
	url: ''
```
## Syntax which worked:
### With proxy, force even if wpscan doesn't think there is WordPress
```bash
wpscan --random-user-agent \
--api-token 'x' --throttle 500 \
--wp-content-dir 'wp-content' --force --login-uri 'wp-login.php' \
--detection-mode aggressive \
--proxy 'socks5://127.0.0.1:9090'
```

> [!References]
> - [GitHub](https://github.com/wpscanteam/wpscan?tab=readme-ov-file)

https://wpscan.com/

https://wpscan.com/wordpress-cli-scanner/

XML RPC