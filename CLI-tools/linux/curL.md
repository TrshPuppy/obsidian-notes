
# curL Command:
The linux `curl` command is a tool used to transfer data to and from a server using various protocols. It's most commonly used with [HTTP](/networking/protocols/HTTP.md) & [HTTPS](/networking/protocols/HTTPS.md) but supports many others including:
- [FTP/S](/networking/protocols/FTP.md)
- [IMAP/S](/networking/protocols/IMAP.md)
- [POP3/S](/networking/protocols/POP3.md)
- [SMB](/networking/protocols/SMB.md)
- [telnet](/networking/protocols/telnet.md)
- etc...
## Usage:
```
curl [options/null]
...
DESCRIPTION
       curl  is  a tool for transferring data from or to a server. It supports these protocols: DICT, FILE, FTP, FTPS, GOPHER, GOPHERS, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT, POP3, POP3S, RTMP, RTMPS, RTSP, SCP, SFTP, SMB,
       SMBS, SMTP, SMTPS, TELNET, TFTP, WS and WSS. The command is designed to work without user interaction.

       curl offers a busload of useful tricks like proxy support, user authentication, FTP upload, HTTP post, SSL connections, cookies, file transfer resume and more. As you will see below, the number of features will make  your
       head spin.

       curl is powered by libcurl for all transfer-related features. See libcurl(3) for details.
```
### Useful options:
#### `curl -I` Headers only:
**HTTP/S, FTP & FILE:** This flag will tell `curl` to only retrieve and return the headers from the response. This is useful *specifically for pentesting/ cybersecurity* because less data is transferred in the target server's response.
#### `curl -L` Follow all re-directs:
**HTTP:** if the server responds with a `3xx` response code (the webpage has been moved), `curl` will follow all redirects by redoing the request using the new URL. The data returned will be from the new location the redirect points to. 
#### `curl -H "header: string"` Setting custom headers:
**HTTP, IMAP, & SMTP:** The `-H` flag will allow you to set custom headers *in addition to the ones sent by default* (however, if you set a header which happens to match one of the defaults, your value will be sent instead of the default's).
#### `curl -X` Setting the request method
**HTTP only:** With the `-X` flag you can set the [request method](/www/request-methods.md) type ()
With

> [!Resources]
> `man curl`

