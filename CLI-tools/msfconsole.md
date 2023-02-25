
Command used to interact with the #metapsloit console. 
- allows you to interact w/ #modules in the framework.

## Usage:
```
msfconsole
```

## Variables:
==NOTE:== Metasploit is subject to its context. If a variable is set in one module, and then the module changes, the variable will be reset.
- #global-variables will not change when changing modules


## Useful options/ commands:
*supports most linux commands*
Types of payloads:
- How to identify a #single (of #inline) vs #stage d payload:
	- single: `generic/shell_reverse_tcp`
	- #staged : `windows/x64/shell/reverse_tcp`
	- the `"_"` between `shell` and `reverse` in the single tells you it is a single (wheras staged uses a `"/"`)

`ls`:
- the 'ls' command will list the contents of the folder from which Metasploit was launched.

``ping``:
- ping will send a ping to Google's DNS IP address (8.8.8.8)
- ```ping -c 1``` will only send one ping instead of continuing to ping until it's told to stop

`use`
`show options`:
- 