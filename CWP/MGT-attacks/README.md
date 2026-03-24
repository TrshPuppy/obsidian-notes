---
aliases:
  - MGT attacks
---
# MGT Attacks
MGT network refer to [wifi](../../networking/wifi/802.11.md) networks ([WPA/WPA2](../../networking/wifi/WPA-WPA2.md) and [WPA3](../../networking/wifi/WPA3.md)) which are using an [Enterprise](../../networking/wifi/enterprise-mode.md) configuration. Enterprise configurations are sometimes referred to as "managed mode" or just *"MGT"*. The difference between an enterprise wifi network and a non-enterprise network (usually called "Personal") is that each client *authenticates individually* with their own username/ password or via a certificate (rather than a shared password).

Most enterprise wifi networks use a *RADIUS server* to help authenticate individual clients. Each client has their own *identity* they use to authenticate.