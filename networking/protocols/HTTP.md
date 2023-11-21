
# Hypertext Transfer Protocol
HTTP is the protocol used to exchange data *on the Web* between a server and a client. It's a 'client-server' protocol, meaning the recipient of the data *initiates the exchange* with a request. The recipient is *usually a web browser*.

Unlike some client-server protocols, messages b/w client and server over HTTP is via individual messages (instead of a stream of data). Messages from the client/ browser are normally *the request*. Messages from the server are *normally the response*.
## Components:
### Client/ User-Agent
The *User-Agent* refers to any tool which acts on behalf of the user and is normally done by the browser. The browser *is always the one requesting from the server*. It normally requests the [HTML](/coding/languages/HTML.md) document which represents a page of a website.

The browser parses the HTML file sent back by the server, and then makes additional requests as it comes across scripts, layout info (CSS), and other resources contained in the HTML page.
### Web Server
The Web Server is a single device, *or a collection of devices* which host software server instances which respond to requests and *serve* the documents requested.
### Proxies
Because the internet is a a bunch of tubes ;) the route between the browser and the server is *not direct*. Instead, the messages from both are relayed through numerous other computers. Most of these [proxy](www/proxy.md) computers operate at the [transport layer](/networking/OSI/transport-layer.md) of the [OSI model](/networking/OSI/OSI-reference-model.md).

Proxies are *able to change the request/ response* before it reaches its destination. Proxies which do this are referred to as "non-transparent". Proxies which don't alter the data at all are 'transparent'.
## Headers:
### User Agent string
The User Agent request header is a unique string which lets servers and "network peers" identify an application, OS, vendor and/or version of the requesting user agent.


> [!Resources]
> - [MDN: HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)
