
# TREVORspray
TrevorSpray is a password spraying tool. It has multiple modules which can do password spraying as well as username/ user enumeration.
## Use
### Install
```bash
pip install git+https://github.com/blacklanternsecurity/trevorproxy
pip install git+https://github.com/blacklanternsecurity/trevorspray
```
### Enumeration Module
The flag for doing enumeration on a domain is `--recon`. This will return a bunch of information gathered from the target domain including [DNS](../../../../../networking/DNS/DNS.md) `TXT` and `MX` records, and info related specifically to *Office 365*.
```bash
trevorspray --recon victimdomain.com
```
#### Office 365
If the target uses O365, TREVORspray will return to you *whether they're using federated* ([Active Directory](../../../../../computers/windows/active-directory/active-directory.md)), *or managed*. It will also give you:
- tenant name
- *tenant ID*
- other tenant domains
- SharePoint URL
- authentication URLs
- autodiscover
- federation config
- etc.
#### User enum
If you want to enumerate users, you can add the `--users` flag with a list of usernames
```bash
trevorspray --recon victimdomain.com --users usernames.txt
```

> [!Related]
> - [credmaster](credmaster.md)
> - [password-spraying](../../password-spraying.md)

> [!Resources]
> - [GitHub](https://github.com/blacklanternsecurity/TREVORspray)