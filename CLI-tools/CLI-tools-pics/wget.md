# `wget`
Can be used on [Linux](../../computers/linux/README.md) and [Windows](../../computers/windows/README.md).
## Cheat Sheet
### Downloading an Entire Remote Directory Listing
```bash
wget -A txt -m -np  http://192.168.7.1/XXXXXXXX/
```
- `-A`: download all files with .txt extension
- `-m`: Mirror mode: download entire directory recursively
- `-np`: Do not ascend to the parent directory (stays within directory specified in the URL)

