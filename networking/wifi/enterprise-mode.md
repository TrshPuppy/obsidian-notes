---
aliases:
  - WPA3-Enterprise
  - WPA/WPA2-Enterprise
---
# Enterprise Mode
The difference between [WPA3](WPA3.md) and WPA3-Enterprise is that, instead of using a shared key (combined with SAE), clients connect *individually*, usually with the help of a *RADIUS server*. Most users connect with *their own password* or a *certificate* specific to them.

|Feature|WPA3 (Personal)|WPA3-Enterprise|
|---|---|---|
|Authentication|Shared password|Per-user authentication|
|Protocol|SAE|802.1X / EAP|
|Backend server|None|RADIUS server|
|Use case|Home, small office|Enterprise, corporate|
[WPA/WPA2](WPA-WPA2.md) can also be set up in an Enterprise configuration. When [wifi](802.11.md) networks are set up in this way, they are considered to be in "Managed Mode" (MGT) (not to be confused with "managed mode" for wifi interfaces).