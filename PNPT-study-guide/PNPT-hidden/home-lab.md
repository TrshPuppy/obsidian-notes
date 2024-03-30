
# VMWare vs. VirtualBox:

## VMWare Workstation Player:
- doesn't do software virtualization
- doesn't do snapshots (unless u pay)

## Virtual Box:
### Installation:
- Version: 7.0.8
- Root Directory: `R:\a-trshp-does-windows\Oracle\VirtualBox\`
- Default Machine Folder (preferences > general) `R:\a-trshp-does-windows\Oracle\Machines`

#### Extensions:
There are extensions which can be downloaded for Virtual Box. They can be found here: https://www.virtualbox.org/wiki/Downloads

I've made an extensions folder in `R:/a-trshp-does-windows/Oracle/Extensions`.

The extension kit includes:
- RDP support
- disk encryption
- NVMe and PXE boot for Intel cards
- host webcam pass through
- cloud integration
[Documentation](https://www.virtualbox.org/manual/ch01.html#intro-installing)

### Network Settings:
Go to tools > network > NAT network and add a network.

#### NAT (network address translation):
[Documentation](https://www.virtualbox.org/manual/UserManual.html#network_nat)

In Virtual Box, NAT is the easiest way to connect to an outside network from within the VM. The router (from the perspective of the VM) is the *Oracle VM VirtualBox networking engine* which is in charge of mapping traffic to and from the VM.

The engine is placed *between* each VM and the host, meaning VMs cannot talk to each other. The packets sent by the VM are filtered by the engine, which strip the VM's IP information, and replaces it with the hosts. This means that to other computers on the network, or programs on the host *the data looks like it was sent from the VirtualBox program.*

#### IP Addressing
The engine handles IP address allocation b/c it *has its own DHCP server.* This means the VM's IP address is on *a completely different network* from the host's.

Each VM can have multiple network cards (NICs) associated with it. The first on defaults to address `10.0.2.0`, the next one would then be `10.0.3.0`.

##### Loopback:
The VM *does have access to the host's loopback address* which is at `10.0.2.2` from within the VM. The default subnet is a `/24`

##### Disadvantages:
The VM is "invisible" from the outside internet. I.e. it cannot act like a server (unless you do port forwarding).

### Images:
I'm making another folder in `R:\a-trshp-does-windows\Oracle\` called `ISOs` so we can access them later.

#### Kali:
PNPT wants us to use a pre-built VBox from [here](https://www.kali.org/get-kali/#kali-virtual-machines)

##### 7z:
For some reason, we need [7 Zip](https://www.7-zip.org/) to unzip this image in Windows. I'm putting it in `R:\a-trshp-does-windows\7-Zip\`.

##### Path:
This box and its associated stuff lives in `R:\a-trshp-does-windows\Oracle\Machines`. I named it "PNPT-kali". Snapshots will be in `R:\a-trshp-does-windows\Oracle\Machines\Snapshot.

##### Settings/ Configuration:
The clipboard and the drag n' drop are set to "Host to Guest".
- Username: trshpuppy
- Password: starts with 2 letters, inverted
- 4 CPU cores
- 10846 MB base memory
- Network: Adapter 1 = NAT

## PNPT-kali
### Users:
#### kali:
- [x] Need to change password
	- [x] Harden kali@kali password (hint: 1)
- [x] Groups: kali@kali is in a lot of groups r/t programs on the system, keep her there I guess

#### hakcypuppy:
- [x] Add to sudo group
- [x] Give password (hint: int)
- [ ] 



