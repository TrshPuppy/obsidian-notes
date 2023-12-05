
# [Metasploit](cybersecurity/tools/exploitation/metasploit.md) Pattern Create
`pattern_create` is a tool w/i the Metasploit framework which you can use to help find the exact [offset](/nested-repos/PNPT-study-guide/PEH/buffer-overflows/pattern-create.md) from the saved `EIP`/ `RIP` on the stack of a program to the entrance of a frame you're using to overflow in a [buffer overflow](/cybersecurity/TTPs/exploitation/binary-exploitation/buffer-overflow.md) exploit.
## 

To use `pattern_create` simply start `msfconsole`, navigate to `/usr/share/metasploit-framework/tools/exploit` and execute `./pattern_create.rb`.