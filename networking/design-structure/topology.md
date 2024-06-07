
# Network Topology
The physical and logical layout of a network of interconnected devices. The topology of a network effects its efficiency, scalability, performance, and fault tolerance.
## Common Topologies:
### Point to Point
A direct link between two devices or locations. Each connection is a *Dedicate connection*, meaning the path is *secure and exclusive*. Unfortunately, point to point topology is *difficult to scale* by attaching more devices. Separate links have to be established in order to add devices to this topology.
### Bus
Bus topology is made up of a single, *central backbone connection* with devices connected along it. This type of topology is *easy to scale* because you can just keep adding devices to the backbone.
#### Collisions
The major downside of this topology is that data from multiple devices can *easily collide* since they're being transmitted across a single connection simultaneously.
![](networking-pics/topology-1.jpg)
### Ring
Networks in a ring topology have devices connects together in a closed-loop. Each device is connected *to two other devices.* Ring networks are *highly fault tolerant*because if a cable or device fails, data can still travel around the ring in the opposite direction.
#### Complexity
Ring networks are a little complex to set up. they require *special protocols* to be configured which manage network recovery in the case of failures.
![](networking-pics/topology-2.jpg)
### Star/ Hub & Spoke
Star networks have a central device which is normally a [hub](OSI/1-physical/hubs.md) or [switch](OSI/2-datalink/switches.md). These central hubs connect to all of the devices on the network. This type of topology is *simplistic* and straight forward to set up. However, the biggest disadvantage is *the central hub is a single point of failure*. If it fails, the entire network suffers and has *no fault tolerance*.
![](networking-pics/topology-3.jpg)
### Tree
Tree topology has a *hierarchical structure*. There is normally a *root node* (usually a central hub or switch) connected to multiple *secondary nodes* and/ or *branches*. Tree networks are *highly scalable* because adding secondary nodes and branches accommodates for added devices of sub networks.
#### Single point of failure
Tree topology networks are vulnerable because they have a *single point of failure* where the entire network will go down if it goes down. If the *root node* fails, there is no redundancy or fault tolerance to allow the rest of the network to continue.
![](networking-pics/topology-4.jpg)
### Mesh
In mesh network topology *every device is connected to every other device*. This adds a *lot of redundancy* so this type of network is not vulnerable to single point of failure. Because all devices are connected, *there are multiple paths for data to take* from one point to another.
#### Complexity and cost
This type of topology *can be expensive to set up* because each device is required to be connected to every other device. This also makes this topology *difficult to scale*.
![](networking-pics/topology-5.jpg)
### Hybrid
A hybrid network design uses *a combination of the previous topologies*. This allows it to provide for specific requirements in the network. These networks are *flexible* but also take on both the advantages and disadvantages of the other topologies it uses.
#### Complexity
These networks can be complex to set up and maintain. Careful planning is required to ensure seamless data transmission between devices and sub networks.
![](networking-pics/topology-6.jpg)

> [!Resources]
> - Internship self-study materiali