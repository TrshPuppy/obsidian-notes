
# Bridge Networking Device
A device which operates on the [data-link-layer](data-link-layer.md) of the [OSI-reference-model](../OSI-reference-model.md). It's primary function is to connect and filter traffic b/w different *segments* of a network.
## Use
Bridges are used to divide large networks into smaller, more manageable sections. Bridging segments also reduces *collision domains* because each segment is *independent*. Like [switches](switches.md), bridges also keep a *MAC address table* to help with remembering devices so it can easily forward frames to them.