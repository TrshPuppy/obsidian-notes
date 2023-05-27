
# [Application Layer](/networking/OSI/application-layer.md) of a Server:
The Server needs to be able to keep track of how many bytes have been received AND what format they are in when it receives a message. The app layer helps you keep track of whether you've received the entirety of one message sent to it).

The start and end of an entire message are called **"message boundaries"*.

## Ways to do this:
### fixed length messages:
Inefficient if you receive messages smaller than fixed length (have to be padded)

### Headers:
Including a header with content length (+ other custom fields) tells the server how many bytes to accept before the message is complete.

*Messages are in raw bytes* including the header. If the server's native CPU has a different [*"CPU endianness"*](https://realpython.com/python-sockets/#byte-endianness) than the CPU which sent the message, the server won't be able to interpret the header.

The header needs to be converted to the server CPU's "native byte order" (endianness).

Having the Application Layer define the header as [Unicode and UTF-8](https://docs.python.org/3/library/codecs.html#encodings-and-unicode) can take care of this (?)

#### Determining your machine's byte order (python):
```bash
python -c 'import sys; pring(repr(sys.byteorder))'
'little'
# Or could be
'big'
```

## Application Protocol Header:







> [!Links]
> [Python Socket Programming](https://realpython.com/python-sockets/#application-client-and-server)