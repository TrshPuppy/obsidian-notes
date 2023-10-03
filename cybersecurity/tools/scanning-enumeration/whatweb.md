
# WhatWeb - Web technology recon
[WhatWeb](https://github.com/urbanadventurer/WhatWeb) is a command line utility written in [ruby](/coding/languages/ruby.md) used to enumerate the technology and services used to create and run a target website.
## Usage:
```bash
.$$$     $.                                   .$$$     $.         
$$$$     $$. .$$$  $$$ .$$$$$$.  .$$$$$$$$$$. $$$$     $$. .$$$$$$$. .$$$$$$. 
$ $$     $$$ $ $$  $$$ $ $$$$$$. $$$$$ $$$$$$ $ $$     $$$ $ $$   $$ $ $$$$$$.
$ `$     $$$ $ `$  $$$ $ `$  $$$ $$' $ `$ `$$ $ `$     $$$ $ `$      $ `$  $$$'
$. $     $$$ $. $$$$$$ $. $$$$$$ `$  $. $  :' $. $     $$$ $. $$$$   $. $$$$$.
$::$  .  $$$ $::$  $$$ $::$  $$$     $::$     $::$  .  $$$ $::$      $::$  $$$$
$;;$ $$$ $$$ $;;$  $$$ $;;$  $$$     $;;$     $;;$ $$$ $$$ $;;$      $;;$  $$$$
$$$$$$ $$$$$ $$$$  $$$ $$$$  $$$     $$$$     $$$$$$ $$$$$ $$$$$$$$$ $$$$$$$$$'

WhatWeb - Next generation web scanner version 0.5.5.
Developed by Andrew Horton (urbanadventurer) and Brendan Coles (bcoles)
Homepage: https://morningstarsecurity.com/research/whatweb

Usage: whatweb [options] <URLs>

TARGET SELECTION:
  <TARGETs>             Enter URLs, hostnames, IP addresses, filenames or
                        IP ranges in CIDR, x.x.x-x, or x.x.x.x-x.x.x.x
                        format.
  --input-file=FILE, -i Read targets from a file. You can pipe
                        hostnames or URLs directly with -i /dev/stdin.

TARGET MODIFICATION:
  --url-prefix          Add a prefix to target URLs.
  --url-suffix          Add a suffix to target URLs.
  --url-pattern         Insert the targets into a URL. Requires --input-file,
                        eg. www.example.com/%insert%/robots.txt 

AGGRESSION:
  The aggression level controls the trade-off between speed/stealth and
  reliability.
  --aggression, -a=LEVEL Set the aggression level. Default: 1.
  Aggression levels are:
  1. Stealthy   Makes one HTTP request per target. Also follows redirects.
  3. Aggressive If a level 1 plugin is matched, additional requests will be
      made.
  4. Heavy      Makes a lot of HTTP requests per target. Aggressive tests from
      all plugins are used for all URLs.

HTTP OPTIONS:
  --user-agent, -U=AGENT Identify as AGENT instead of WhatWeb/0.5.5.
  --header, -H          Add an HTTP header. eg "Foo:Bar". Specifying a default
                        header will replace it. Specifying an empty value, eg.
                        "User-Agent:" will remove the header.
  --follow-redirect=WHEN Control when to follow redirects. WHEN may be `never',
                        `http-only', `meta-only', `same-site', or `always'.
                        Default: always.'
  --max-redirects=NUM   Maximum number of contiguous redirects. Default: 10.

AUTHENTICATION:
  --user, -u=<user:password> HTTP basic authentication.
  --cookie, -c=COOKIES  Provide cookies, e.g. 'name=value; name2=value2'.
  --cookiejar=FILE      Read cookies from a file.

PROXY:
  --proxy           <hostname[:port]> Set proxy hostname and port.
                    Default: 8080.
  --proxy-user      <username:password> Set proxy user and password.

PLUGINS:
  --list-plugins, -l            List all plugins.
  --info-plugins, -I=[SEARCH]   List all plugins with detailed information.
                                Optionally search with keywords in a comma
                                delimited list.
  --search-plugins=STRING       Search plugins for a keyword.
  --plugins, -p=LIST  Select plugins. LIST is a comma delimited set of 
                      selected plugins. Default is all.
                      Each element can be a directory, file or plugin name and
                      can optionally have a modifier, eg. + or -
                      Examples: +/tmp/moo.rb,+/tmp/foo.rb
                      title,md5,+./plugins-disabled/
                      ./plugins-disabled,-md5
                      -p + is a shortcut for -p +plugins-disabled.

  --grep, -g=STRING|REGEXP      Search for STRING or a Regular Expression. Shows 
                                only the results that match.
                                Examples: --grep "hello"
                                --grep "/he[l]*o/"
  --custom-plugin=DEFINITION\tDefine a custom plugin named Custom-Plugin,
  --custom-plugin=DEFINITION  Define a custom plugin named Custom-Plugin,
                        Examples: ":text=>'powered by abc'"
                        ":version=>/powered[ ]?by ab[0-9]/"
                        ":ghdb=>'intitle:abc \"powered by abc\"'"
                        ":md5=>'8666257030b94d3bdb46e05945f60b42'"
  --dorks=PLUGIN        List Google dorks for the selected plugin.

OUTPUT:
  --verbose, -v         Verbose output includes plugin descriptions. Use twice
                        for debugging.
  --colour,--color=WHEN control whether colour is used. WHEN may be `never',
                        `always', or `auto''.
  --quiet, -q           Do not display brief logging to STDOUT.
  --no-errors           Suppress error messages.

LOGGING:
  --log-brief=FILE        Log brief, one-line output.
  --log-verbose=FILE      Log verbose output.
  --log-errors=FILE       Log errors.
  --log-xml=FILE          Log XML format.
  --log-json=FILE         Log JSON format.
  --log-sql=FILE          Log SQL INSERT statements.
  --log-sql-create=FILE   Create SQL database tables.
  --log-json-verbose=FILE Log JSON Verbose format.
  --log-magictree=FILE    Log MagicTree XML format.
  --log-object=FILE       Log Ruby object inspection format.
  --log-mongo-database    Name of the MongoDB database.
  --log-mongo-collection  Name of the MongoDB collection. Default: whatweb.
  --log-mongo-host        MongoDB hostname or IP address. Default: 0.0.0.0.
  --log-mongo-username    MongoDB username. Default: nil.
  --log-mongo-password    MongoDB password. Default: nil.  
  --log-elastic-index     Name of the index to store results. Default: whatweb 
  --log-elastic-host      Host:port of the elastic http interface. Default: 127.0.0.1:9200
  
PERFORMANCE & STABILITY:
  --max-threads, -t       Number of simultaneous threads. Default: 25.
  --open-timeout          Time in seconds. Default: 15.
  --read-timeout          Time in seconds. Default: 30.
  --wait=SECONDS          Wait SECONDS between connections.
                          This is useful when using a single thread.

HELP & MISCELLANEOUS:
  --short-help            Short usage help.
  --help, -h              Complete usage help.
  --debug                 Raise errors in plugins.
  --version               Display version information. (WhatWeb 0.5.5).

EXAMPLE USAGE:
* Scan example.com.
  ./whatweb example.com
* Scan reddit.com slashdot.org with verbose plugin descriptions.
  ./whatweb -v reddit.com slashdot.org
* An aggressive scan of wired.com detects the exact version of WordPress.
  ./whatweb -a 3 www.wired.com
* Scan the local network quickly and suppress errors.
  whatweb --no-errors 192.168.0.0/24
* Scan the local network for https websites.
  whatweb --no-errors --url-prefix https:// 192.168.0.0/24
* Scan for crossdomain policies in the Alexa Top 1000.
  ./whatweb -i plugin-development/alexa-top-100.txt \
  --url-suffix /crossdomain.xml -p crossdomain_xml
```
### Other useful flags:
#### `--verbose`
Verbose output which describes what the output means.
#### `--v`: really verbose:
Really verbose shows how ea plugin was matched and is helpful for debugging plugins.
#### `--user-agent=AGENT`:
Lets you set your own user agent for the request. Defaults to `WhatWeb/0.5.5` if not specified, and will not send the `User-Agent` header if set to `--user-agent=""`.
### Aggression:
WhatWeb can be set to 3 levels of aggression w/ the `-a` flag:
1. Stealthy: only one HTTP request + redirects per target
2. Unused
3. Aggressive: Makes multiple [HTTP](/networking/protocols/http.md) requests per target. Also triggers *aggressive plugins* (plugins which have the option to be ran at level 2), but only if their targets are "identified with a level 1 request first".
4. Heavy: Even more HTTP requests per target *and all aggressive tests from all plugins are used for all target URLs* (regardless of whether the target showed up at level 1 aggression)

Each level becomes less stealthy but more accurate in its resultant output. WhatWeb *defaults to level 1* unless the `-a` flag is give.
#### Example of level 3 scan:
```bash
#          * plugin            * aggression
./whatweb -p plugins/phpbb.rb -a 3 smartor.is-root.com/forum/
http://smartor.is-root.com/forum/ [200] phpBB[2,>2.0.20]
#                                        |---> phpBB v2.0.20
```
### Logging & Output:
There are many `--log-x` flags you can give whatweb to do logging of your output.
## Plugins:
WhatWeb can be run with or without plugins. Plugins are community-written modules which you can add to a scan to get more details on specific systems based on signatures.

They can have additional aims including identifying service versions, modules, usernames and accounts, etc.. Other plugins aim to discover or identify unanticipated systems (hashes, title of page, uncommon HTTP headers, etc.).
### Methods:
There are four main methods to identify website technology which plugins can achieve:
1. Matching patterns in HTTP headers and HTML in a simple webpage request
2. Identifying patterns in the HTML by testing for URLs.
3. Recognizing the MD5 hash by testing for URLs
4. Testing URLs and noting that they exist or at least return an HTTP 200 status code

Method 1 is the most common and returns the most information for the time spent. Methods 2 thru 4 are less common and are mostly used in aggressive (level 3 plugins).
### Filesystem:
On Kali linux the directories for plugins and used by plugins can be found in `/usr/share/whatweb`. This dir includes `plugins` and `my-plugins`. If developing a plugin, you may also need to add: `plugin-development` and `plugin-development/tests/`.
### Anatomy of a plugin:
#### Header:
At the top of a ruby plugin file (`.rb`), the header declares the plugin in sections.
```ruby
1. Plugin.define "Drupal" do
2. author "Andrew Horton"
3. version "0.1"
4. description "Drupal is an opensource CMS written in PHP. Homepage: http://www.drupal.org"
```
Line 1 is the name of the plugin and can be used to refer to it in the command line (case sensitive). 
#### Variables:
There are only a handful of variable names which can be defined in a plugin including `author, version, description, examples, matches, dorks`.
##### var Examples:
Examples have to be listed in a ruby array using `%w|`. This notation in ruby means an array of elements separated by whitespace:
```ruby
examples %w| example.com/ also-example.com https://example-3.com |
# OR:
examples %w| 
example.com/
http:also-example.com/
www.example-3.com/
|
```
If `http://` or `https://` is not included, then `http://` is assumed by WhatWeb.
##### var Matches:
A list of patterns to match against the webpage. The strings should be in an array and each should be surrounded by `{}`.
```ruby
 matches [
17. {:name=>"/misc/drupal.js",
18. :regexp=>/<script type="text\/javascript" src="[^\"]*\/misc\/drupal.js[^\"]*"><\/script>/},
29. 
20. {:name=>"Powered by link",
21. :regexp=>/<[^>]+alt="Powered by Drupal, an open source content management system"/},
22.
23. {:name=>"/misc/drupal.css",
24. :regexp=>/@import "[^\"]*\/misc\/drupal.css"/},
25.
26. {:text=>'jQuery.extend(Drupal.settings,'},
27. 
28. {:text=>'Drupal.extend('}
29. ]
```
Each element of the array is an object which includes the pattern's `name` (optional, but should be unique), and the pattern it matches. There are different ways you can use to make the matching pattern including regex (`:regexp`), plaintext (`:text`), ghdb (Google Hacking Database)(`:ghdb`), MD5 hash (`:md5`) etc..

**NOTE:** slashes `\` need to be escaped with a backslash `/`
#### Functions & Variables:
Functions in plugins can access the following variables:
- `@body`: HTML body (w/i the `<html> </html>` tags, not `<body>`)
- `@meta`: HTTP headers and cookies
- `@status`: The HTTP status code (200  or 404)
- `@base_uri`: The URL
- `@md5_sum`: MD5 hash of the page
- `@tagpattern`: The pattern that opening and closing HTML tags follow
- `@ip`: IP address of the page as a string

Functions can be one of the following: passive, aggressive, startup, or shutdown.
## Writing a Plugin for a Service:
[WhatWeb GitHub: Research background info](https://github.com/urbanadventurer/WhatWeb/wiki/How-to-develop-WhatWeb-plugins#3-research-background-information)
### Service/ Software home page:
Go to the service's website and look for anything regarding:
- Requirements: type of web server, languages, it requires etc..
- Demo sites
- Website showcases/ portfolios
- Download links
- Documentation
### Collect samples:
Try to collect samples which represent the service in all of its versions. Don't just choose recent version examples. Collect a variety of samples w/ a range of configurations.

You can use search engines, website portfolios, web dev forums, etc. to source your samples.\

```
https://hsr-showcase.vercel.app/profile?uid=600516595
https://showcase-theme.vercel.app/
https://dynamic--portfolio.vercel.app/
https://portfolyoo.vercel.app/
https://responsive-portfolio-website-zeta.vercel.app/
https://designo-portfolio-website.vercel.app/
https://portfolio-website-design.vercel.app/
https://portfolio-sagar.vercel.app/
https://www.gaylemanningdesigns.com/
https://ftcportfolio.vercel.app/
```
#### Using Search Engines:
Besides just searching for things like `vercel porfolio sites` or `vercel showcase`, you can use [Google Dorking](/cybersecurity/TTPs/recon/google-dorking.md) which is much more powerful.

Google Dorking is essentially searching for intelligence/ info on the web using specifically crafted strings called 'google dorks.'

The [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) is a huge database organized by [Exploit DB](cybersecurity/tools/exploitation/exploit-db.md) of google dorks people have used with success to find specific services, etc..

Even though google dorking can be very useful, it is a known TTP, so webmasters avoid and remove strings which are dorkable in order to reduce discoverability. 

For example, Wordpress sites can sometimes include the footer "Powered by Wordpress" which is easy to grep via Google Dorks, so most Wordpress sites know to get rid of it.

> [!Resources]
> [WhatWeb GitHub](https://github.com/urbanadventurer/WhatWeb)
> [How to Develop WhatWeb Plugins](https://github.com/urbanadventurer/WhatWeb/wiki/How-to-develop-WhatWeb-plugins)

> [!My previous notes (linked in the text)]
> - [HTTP](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/protocols/HTTP.md)
> - [ruby](https://github.com/TrshPuppy/obsidian-notes/blob/main/coding/languages/ruby.md)

