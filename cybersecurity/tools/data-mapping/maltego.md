
# Maltego
[Maltego](https://www.maltego.com/) is an [OSINT](/cybersecurity/TTPs/recon/OSINT.md) tool which creates visual graphs to help organize enumerating public sources of information on a target. Maltego gathers data from sources including public websites, emails, social media, crypto transactions, etc..

In [penetration-testing](/cybersecurity/pen-testing/penetration-testing.md) it's used to crate a visual representation of a target's digital landscape.
## Transforms
Transforms in Maltego are pieces of code which process information. Each takes an Entity, which is a defined piece of data like an [IP address](/networking/OSI/IP-addresses.md) or email, and searches for information related to it.
## Usage
**NOTE:** You have to register for an account to use Maltego (it's free). This will give you an API key.
### Installation
If Maltego isn't already on the machine:
```bash
sudo apt install -y maltego
```
### Installing a Transform
Go to the 'Transform Hub' to find transforms to install. Transforms can be organized by the various radio options. An example of a good transform is [Censys](https://censys.com/) which you can use to map IP addresses of a target.

Some transforms require an API key from the service, like Censys. Once you make an API key, you can install Censys from Maltego and start using it.
### Machine Investigations
In Maltego, Machines under the Machines tab can be used to start an investigation. An example of a Machine is the 'Company Stalker' machine. Given a target domain name and a browser to use, it will enumerate emails on the target.
![](/cybersecurity/cybersecurity-pics/maltego-1.png)
### Manual Investigation
To start your own investigation w/o the help of a machine, click 'New' in the top left-hand corner. This will start a new project.

A new graph will open and on the left you can find the Entity Palette. This is where you can choose an entity to investigate on the target. Drag the entity you want to investigate onto the graph.