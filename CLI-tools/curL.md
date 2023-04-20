
# curL Command:

### Usage:
```
curl [options/null]
```

A cli tool for transferring data from or to a server
	supports many various protocols (ex: #HTTP, #HTTPS, #FTP, #SMB #TELNET)

#### Useful options:
- #curl-I
	- syntax: ``curl -I $URL``
		- only fetches headers from the url
		- SECURITY 
		- With #HTTP: uses the HEAD command in the get request(?
		- With #FTP:
			- returns the file size and last modification time
- #curl-L
	- syntax: ``curl -L $URL``
	- location!
		- with #HTTP:
			- if the requested page has moved to a different location, (indicated w/ a ``Location`` header and #3xx response code)
				- curl will redo the request to the new place
			- If used w/ ``-I`` (headers only) curl will return headers from all requested pages