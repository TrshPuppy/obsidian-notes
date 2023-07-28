
# WSTG-INFO-01: Conduct Search Engine Recon for Info Leakage
**SUMMARY**: Search engines work by using bots to *crawl* billions of web pages searching for embedded links and sitemaps. Web pages can use a special file called `robot.txt` to blacklist pages and prevent them from being fetched by search engines.
>	See: [How Search Engines Work](https://developers.google.com/search/docs/fundamentals/how-search-works?hl=en&visit_id=638260579591177855-1863182502&rd=1)

When a search engine robot finishes crawling, it indexes the web content according to related tags and attributes (like `<Title>` in an [HTML](/coding/markup/HTML.md) file).

If the `robot.txt` file of the site isn't updated regularly (or not created at all) then its possible for web indexes to contain content *not intended to be there* by the site owners. Unwanted content can be removed by using the `robot.txt`, HTML meta tags, authentication, etc..

There are both *direct* and *indirect* methods of search engine discovery/recon. Direct methods include searching indexes and associated content found in caches. Indirect methods r/t learning sensitive configuration and design info by browsing sources like forums, newsgroups, etc..

**OBJECTIVES**: "Identify what sensitive design and configuration info. of the application, system, or organization is exposed directly (on the organization's site) or indirectly (via third-party services)."

> [!Resources]
> - [WSTG-INFO-01](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage.md)
> - [Google: How Search Engines Work](https://developers.google.com/search/docs/fundamentals/how-search-works?hl=en&visit_id=638260579591177855-1863182502&rd=1)
> - 