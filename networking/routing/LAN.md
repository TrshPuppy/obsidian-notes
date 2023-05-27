
# Local Area Network (LAN)
A LAN is a network of computers all occupying the same range of IP addresses. They are usually connected via switches and routers

## Types of Devices:
### Switches:
A switch is a dedicated device in a network designed to aggregate other devices including computers, printers etc.. Each device plugs into the switch's ports and the switch keeps track of which device is connected to which port:

Switches are more efficient than hubs and repeaters because when they receive a packet they're able to send it to the right device instead of just sending it to every connected device, hoping that the right device will receive it. This reduces network traffic.

Switches can also be connected to routers which helps *increase network redundancy*. They can operate on either [L2](/networking/OSI/data-link-layer.md) or [L3](/networking/OSI/network-layer.md) but *can't do both*.

#### L2 Switches:
Can only forward frames to connected devices using their [MAC addresses](/networking/OSI/MAC-addresses.md).
![](/networking/networking-pics/LAN-1.png)
>	[TryHackMe](https://tryhackme.com/room/extendingyournetwork)

#### L3 Switches:
L3 switches *can do some of the things routers can do*. They can send frames to connected L2 devices, and will use IP protocol to route packets to L3 devices.

![](/networking/networking-pics/LAN-2.png) 
>	[TryHackMe](https://tryhackme.com/room/extendingyournetwork)

#### Routers:
A router connects networks so data can be passed between them. They use [routing tables](/networking/routing/routing-table.md) to route data from different devices across the network. They are considered layer 3 devices.

As it travels, data is given a label and is routed down a path which is decided based on the path's length, reliability, and speed.

## Topologies:
### Star Topology:
Devices are individually connected to a central networking device like a hub or switch. This topology is the most common. Data sent to and from devices travels through the central device.

#### Advantages:
Star topologies are easy to implement and easy to scale.

#### Disadvantages:
As the network grows, so does the maintenance. If the central device fails *there is no redundancy to re-route traffic*. This topology also tends to be expensive.

![](/networking/networking-pics/LAN-3.png)
>	[TryHackMe](https://tryhackme.com/room/introtolan)

### Bus Topology:
A single common connection known as a "backbone-cable". Devices stem off a main branch like leaves.

#### Disadvantages:
All data traveling along main branch = SLOW. Issues which arise are difficult to troubleshoot. There is also no redundancy in case of failure.

#### Advantages:
Easy to set up and cost effective.
![](/networking/networking-pics/LAN-4.png)
>	[TryHackMe](https://tryhackme.com/room/introtolan)


### Ring Topology:
Also called "token-topology." Data is sent around the loop *to each device* until it reaches the one it was addressed for. If a device has its own data to send, it will send its own first, then the transferring data.

#### Advantages:
Easy to troubleshoot issues. Less prone to bottle-necking.

#### Disadvantages:
A fault along the cable will cause entire network to crash. Also not efficient way of sending data since devices wait to send their own data before receiving  data sent to them.
![](/networking/networking-pics/LAN-5.png)
>	[TryHackMe](https://tryhackme.com/room/introtolan)

> [!Resources:]
> - [TryHackMe: Extending your Network](https://tryhackme.com/room/extendingyournetwork)
> - [TryHackMe: Intro to LAN](https://tryhackme.com/room/introtolan)

