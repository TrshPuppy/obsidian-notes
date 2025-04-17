
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
### Useful Flags
#### `-e`: enumerate
Choose how `wpscan` enumerates the target. Options include:
- `vp`: vulnerable plugins
- `ap`: all plugins
- `p`: poplular plugins
- `vt`: vuln themes
- `at`: all themes
- `t`: popular themes
- `tt`: Timthumbs
- `cb`: config, backups
- `dbe`: DB exports
- `u`: user IDs range (ex: u1-5)
- `m`: media IDs range - set permalink setting to 'Plain' so permalinks can be detected
The default is all plugins, config backups (`ap`, `cb`).  If no value is supplied, then `wpscan` will use `vp`, `vt`, `tt`, `cb`, `dbe`, `u`, and `m`.
##### Example
```bash

```
## Syntax which worked:
### With proxy, force even if wpscan doesn't think there is WordPress
```bash
wpscan --random-user-agent \
--api-token 'x' --throttle 500 \
--wp-content-dir 'wp-content' --force --login-uri 'wp-login.php' \
--detection-mode aggressive \
--proxy 'socks5://127.0.0.1:9090' \
--url 'https://target.com'
```

> [!References]
> - [GitHub](https://github.com/wpscanteam/wpscan?tab=readme-ov-file)
> - [WPScan Website](https://wpscan.com/)

