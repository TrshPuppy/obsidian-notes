
# Go Programming Language
## Environment
### $GOROOT
Should be set to the directory where go was installed. Do **NOT** set it to `<go-install-directory>/go/bin` because Golang will use `GOROOT` to set other environment variables such as `GOTOOLDIR`.

If you set `GOROOT` to `/go/bin` then your `GOTOOLDIR` will default to `.../go/bin/pkg/tool/...`. But this should really be set to `.../go/pkg/tool`.
### $GOPATH
### $GOTOOLDIR
Where Golang will go to search for tools it needs to run in your specific OS environment. **YOU SHOULD NOT SET IT YOURSELF**, the golang env will set it for you (probably based on `GOROOT`).

It should look something like: `.../go/pkg/tool/linux_amd64` (if you're coding in a linux environment).
