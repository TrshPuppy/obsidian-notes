
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
Because the internet is a a bunch of tubes ;) the route between the browser and the server is *not direct*. Instead, the messages from both are relayed through numerous other computers. Most of these [proxy](../networking/design-structure/proxy.md) computers operate at the [transport layer](/networking/OSI/transport-layer.md) of the [OSI model](/networking/OSI/OSI-reference-model.md).

Proxies are *able to change the request/ response* before it reaches its destination. Proxies which do this are referred to as "non-transparent". Proxies which don't alter the data at all are 'transparent'.
## Headers:
### User Agent string
The User Agent request header is a unique string which lets servers and "network peers" identify an application, OS, vendor and/or version of the requesting user agent.
## Methods
### `GET`
The `GET` method when sent to a webserver is usually used to request a *representation* of the specified resource. They should be used to request data and *should not have a request body*. However, you can add parameters to the path you're requesting and set those equal to certain values as a way to pass data to the server via `GET`.
### `POST`
### `PUT` & `PATCH`
`PUT` and `PATCH` methods are used to *replace a value* on the server rather than create a new value (like with `POST`).
#### `PUT`
Should be used to create a new resource or *replace a representation* of the target resource using the request's content. The difference b/w `PUT` and `POST` is that calling it multiple times successively *has no side effects* (it's "idempotent"). 

You can put the data you want to create/ replace with in the path as URL parameters, or in the request's body:
```http
PUT /new.html HTTP/1.1
Host: example.com
Content-type: text/html
Content-length: 16

<p>New File</p>
```
If the target resource does not have a current representation, and the `PUT` request successfully creates one, the server should respond with `201 Created` and a `Content-Location` header set to the path value of the new resource.

If the target resources already exists (has a current representation), and the `PUT` request modifies it successfully, the webserver should respond w/ `200 OK` or `200 No Content`. Both indicate a successful request.
#### `PATCH`
Usually implies *partial modification* of a resource. It differs from `PUT` because it serves as a *set of instructions* for modifying a resources (whereas `PUT` is a complete replacement of the resource). Where a `PUT` request is "idempotent," a `PATCH` request may or may not be. This means it has the potential to cause side effects, just like a `POST` request.
##### Example
Let's say a webserver has the following resource which represents a user w/ an ID of `123`:
```json
{
  "firstName": "Example",
  "LastName": "User",
  "userId": 123,
  "signupDate": "2024-09-09T21:48:58Z",
  "status": "active",
  "registeredDevice": {
    "id": 1,
    "name": "personal",
    "manufacturer": {
      "name": "Hardware corp"
    }
  }
}
```
If you want to modify only a specific part of the JSON object, you can do that with a `PATCH` request (whereas a `PUT` might be used to overwrite the entire thing):
```http
PATCH /users/123 HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 27
Authorization: Bearer ABC123

{
  "status": "suspended"
}
```

> [!Resources]
> - [MDN: HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)
> - [MDN: PUT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/PUT)
> - [MDN: PATCH](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/PATCH)
