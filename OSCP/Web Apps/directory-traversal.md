
# Exploiting Directory Traversal
For a web application to use or display content from a specific file in its filesystem, it often has to use directory paths and refer to them directly in the web application's code. Files are sometimes referenced using absolute pathing and sometimes using relative pathing.

In Linux-based web servers, the root web directory is usually `/var/www/` and [HTML](../../cybersecurity/bug-bounties/hackerone/hacker101/HTML.md) files for a website being served from that directory are normally kept in `/var/www/html`. So, for a web server to fetch and serve the `index.html` file, then with this setup, its *relative* path (to the root) would be `./html/index.html`. It's *absolute* path would be `/var/www/html/index.html`.

A web application which is *vulnerable to directory traversal* does not prevent a user of the website from accessing files in other directories. Usually this is mitigated by *input sanitization*. For example, if a user uploads a picture to the webserver to be used as a profile picture. The web app might save that picture in `/var/www/html/assets/users/user1_profile.jpg`. Then, whenever the picture has to be rendered on the page, the web server has to fetch that file.

If the web server doesn't sanitize user input, then a user may choose a profile picture, but save the name of the image as `../../../../../etc/passwd`. Now, when the server has to render their profile picture, it will search for `../../../../../etc/passwd` and serve that file as the user's profile image. 

This is one example of how not sanitizing user input can result in directory traversal, but there are many other ways directory traversal can present itself.
## URL Parameter
Let's say a webpage is hosted at `https://target.com/cms/login.php?language=en.html`. In this case, the webserver is using [PHP](../../coding/languages/PHP.md) and `login.php` is able to process a parameter called `language`. The value of `language` is set to an HTML file, telling us that this parameter takes a file or *filepath* as its value.

If we can navigate to the file `en.html` (`https://target.com/cms/en.html`) then we've confirmed it is a file that exists on the server. *Additionally* we've confirmed *WHERE* it exists on the server (`<web root>/cms/en.html`). This tells us that `/cms` is therefor a subdirectory of the server's web root.
### `?page=`
On websites built using PHP, you might also see the `page` parameter, as in `https://target.com/index.php?page=index.php`. In this situation, the `page` parameter is similar to the `language` parameter of the last example. 

Browsing through the page and hovering over all of the intractable content, you might find more links with different values set for `page`. For example, maybe a section of the webpage is meant to load content from the `admin.php` page and embed it into the content of `index.php`. When we hover over the content, the link preview would look like `https://target.com/index.php?page=admin.php`. 

If we change the url in our browser to the value of this URL, then we should see the contents of `admin.php` loaded into the web page's content. This means the web application is using the `page` parameter to *render the given page's content* and display it on `https://target.com/index.php`. 

If the web application is not configured to sanitize user input, then we can exploit it to perform path traversal and trick the webpage into rendering other files in its filesystem. For example, setting the `page` value in the URL to `../../../../../../etc/passwd` should render the `etc/passwd` file on the page (where `admin.php` would normally be rendered). 
## Windows Web Root
On Linux web servers, the webroot is usually `/var/www`. But on Windows-based web servers like IIS,  the web root is usually `C:\Inetpub\wwwroot`. 

Additionally, to prove exploitability on a windows web server, you might try to traverse to a file like `C:\Windows\System32\drivers\etc\hosts` instead of `/etc/passwd` (which is strictly a Linux file). 
## Character Encoding
Since `../../` is the most recognizable way to test for directory traversal, web application and web app firewalls are usually configured to block it in a query. To get around this, we can use *URL encoding* ("Percent encoding"). 
### Percent Encoding
Percent encoding is primarily used to encode characters so they can easily be transmitted over the internet. When the web server or web browser receives characters which are URL encoded, its configured to be able to decode them into plaintext. 

This can be leveraged for malicious purposes like bypassing web application firewalls. For example, if you want the *plaintext* request `cgi-bin/../../../../../etc/passwd` to be processed by they server, then you can URL encode it in the hopes the server and/or firewall let it pass:
```bash
# curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
alfred:x:1000:1000::/home/alfred:/bin/bash
```

> [!Resources]
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.