
# MAC Addresses

(Media Access Control):
A MAC address is a 48 bit hardware number which is *unique* to the device its attached to.
- usually embedded w/i a device's #network-card / #network-interface-card when the device is manufactured.

Used by the #MAC-sublayer of the [[data-link-layer]].

## Format:
```
Hyphen-Hexadecimal: 00-0a-83-b1-c0-8e
Colon-Hexadecimanl: 00:0a:83:b1:c0:8e
Period-separated: 000.a83.b1c.08e
```
Formatted into a 12 digit #hexadecimal number (6 bytes) represented by #Colon-Hexadecimal, #hyphen-hexadecimanal, or #period-separated-hexadecimal notation.

>[!info]
> Linux uses colon notation
> Cisco uses period-separated

- First six digits = Identifies the manufacturer
	- called the Organizational Unique Identifier ( #OUI)
	- Assigned by the #IEEE to registered vendors
	- ex:
``` 
CC:46:D6 - Cisco
```
- #Network-Interface-Controller (last 6 digits)
	- also assigned by the manfacturer

## MAC Spoofing / #MAC-spoofing:
When a networked device pretends to identify as a different one by using its MAC address.
- Can break poorly-maintained security designs
	- ex: if a network firewall is configured to trust any and all traffic coming from the MAC address of the administrator
>[!Command line]
>[[ifconfig]]
>[[ip-command]]
>