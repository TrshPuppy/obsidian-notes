---
aliases: [fs, node fs, node filesystem]
---
>[!links]
>https://nodejs.org/api/fs.html#file-system
>
>https://www.geeksforgeeks.org/node-js-fs-write-method/

# Node File System
"node:fs enables interacting w/ the file system..."
- #promise -based #API 
	- import syntax: ```import * as fs from 'node:fs/promises';*```

## Open/read/write a file:
part of the #Callback-API:
- #Callback-API performs actions #asyncronous ly (**take care when performing multiple changes to a file bc it may corrup the file's data).
- syntax:
	- ```fs.write(fd, buffer/string, offset/position, position/encoding, callback)```
		- parameters:
			- *fd:* file descriptor: the value returned by ```fs.open()``` method. Type = integer
			- *buffer:* contains buffer type value
			- *offset:* integer which determines the part of the buffer to to be written to the file
			- *length:* integer value which specifies the # of bytes to write into file
			- *position:* int value which is the position from the beginning of the file where the data to be written is
			- *callback:* callback function which receives error and number of bytes to be written to file
			- *string:* write string to the file specified by fd
			- *encoding:* default value is UTF-8
		- return:
			- callback function receives either the error or the number of bytes to be written (*length*). If an error is received then the error message is printed. Else, the number of bytes written is printed.
		- **using buffer vs string** 
			- A string can be used instead of a buffer to write to the file
			- syntax:
				- ```fs.write(fd, string, position, encoding, callback)``` 