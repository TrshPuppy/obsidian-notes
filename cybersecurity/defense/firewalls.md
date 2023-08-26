
# Firewalls
Device w/i a network responsible for determining what traffic can enter and exit.
- Can be hardware or software

## Configuration Factors:
Firewalls use packet inspection to determine:
- Where is the traffic ==coming from== (has the firewall been configured to deny traffic from specific sources)?
- Where is the traffic ==going to== (has it been configured to deny traffic from going to a specific network)?
- What ==port is the traffic for== (has it been configured to deny traffic destined for a specific port)?
- What ==protocol== is the traffic using (has it been configured to deny traffic which is #UDP / #TCP or both)?

## Types/ Categories:
1. Stateful / #stateful-firewall:
	- Instead of examining a single packet from a connection, stateful firewalls ==examine the entire connection==
		- #stateful-packet-inspection
	- Resource-heavy
	- If connection is found to be bad, the ==entire connection is blocked==
2. Stateless / #stateless-firewall:
	- Compares individual packets against a set of static rules to decide if ea packet is acceptable or not.
		- If one packet from a device is bad, the entire device ==will not be blocked==
	- use fewer-resources
	- =="DUMB"==
		- only as effective as their set of rules
		- if a bad packet does not exactly match a rule, it will not be caught
	- ==Better for [[cybersecurity/TTPs/exploitation/denial-of-service]] attacks==
		- https://www.netscout.com/sites/default/files/2021-10/SECWP_020_EN-2101%20-%20Enemy%20of%20the%20State.pdf