
# Google Fu
How to optimize google searching in the context of Recon and Information gathering.

## Google Search Operators:
[Ahrefs: Google Search Operators, The Complete List](https://ahrefs.com/blog/google-advanced-search-operators/)

Advanced search operators in google can be used to optimize and filter search results.

## Enumerating subdomains:
To enumerate subdomains using Google dorks you can simply add `+-www` to your search: `site:google.com`.
```bash
# Search in google search bar:
site:google.com -www

# Actual URL:
https://www.google.com/search?q=site:facebook.com+-www
```

> [!Resources]
> - [Ahrefs: Google Search Operators, The Complete List](https://ahrefs.com/blog/google-advanced-search-operators/)