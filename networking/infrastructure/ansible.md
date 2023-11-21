
# Ansible
[Ansible](https://docs.ansible.com/ansible/latest/getting_started/index.html) is a tool used to automate remote IT systems. It is open source and owned by Redhat. It is based on python, and uses OpenSSH. 

Ansible automation works as a push-based system, meaning the main control node *pushes* changes to the nodes it manages (as opposed to a pull-based system where the managed nodes have to pull down changes from the control node).

It has three main components:
## Components:
### Control Node:
A system on which ansible is installed. Commands r/t to ansible can be run on a control node including `ansible` or `ansible-inventory`.
### Managed Node:
A remote system or host which ansible controls.
### Inventory:
A list of managed nodes which are logically organized. An inventory can be created on the control node to describe host deployments to ansible.
## [Install:](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)
For a control node machine, you can use any Unix-based OS with Python 3.9+ installed.

For managed nodes, Ansible does not need to be installed, but the node does require Python 2,7 or Python 3.5-3.11 installed to run Ansible library code. The managed nodes also need a user account that can [SSH](/networking/protocols/SSH.md) to the control node(?) with an interactive POSIX shell.
## Control Node:
Once Ansible is installed, find the ansible directory on the control node:
```shell
$ cd /etc/ansible
$ ls
ansible.cfg hosts roles
```
- `ansible.cfg` is the configuration file
- `hosts` is a list of managed nodes
### `hosts` file:
Also called the "Inventory." Lists all of the machines/ things the control node controls including linux machines, routers, switches, etc.
```shell
$ sudo nano hosts
```

Once w/i the hosts file via nano/ vim:
```shell
# Create a group by surrounding the name in brackets:
[linux]
# to add hosts: list the IP addresses of the managed nodes under the group name:
69.69.69.6
69.69.69.9

# To add some attributes to the group or manages nodes:
[linux:vars]
ansible_user=<username>
ansible_password=<password>
```
### `ansible.cfg` file:
Once you've opened the `ansible.cfg` file using nano/ vim:
```shell
## The following option should be TRUE in production
## For development you can set this option to False
host_key_checking = False
```
### Command Line:
Once these basic settings are placed, you can use ansible in the CLI:
#### Ping managed nodes:
```shell
# ping nodes by passing their group name as an arg to ansible:
$ ansible linux -m
69.69.69.6 | SUCCESS => {
	"ansible_facts":{
		"discovered_interpreter_python": "/usr/bin/python"
		},
		"changed":"false",
		"ping":"pong"
}
69.69.69.9 | SUCCESS => {
"ansible_facts":{
		"discovered_interpreter_python": "/usr/bin/python"
		},
		"changed":"false",
		"ping":"pong"
}
$
```
#### Run commands on managed nodes:
```shell
# the -a switch means "adhoc" or "on the fly"
$ ansible linux -a "cat /etc/os-release"
69.69.69.9 | CHANGED | rc=0 >>
NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
... 
# (etc)
```
## Playbook:
A playbook is a #YAML (data serialization language) file. The YAML Playbook file contains tasks that you want to run on managed nodes:
### Create a Playbook:
*Example:* create a [YAML](/coding/languages/YAML.md) Playbook file called "iluvnano.yml"
```YAML
--- # these dashes denote a YAML file
	- name: iluvnano # this is a "play"
	  hosts: linux # the group defined in the host file
	  tasks:
		- name: ensure nano is there # this is a "task"
		  yum: # this is a "module" (small program which define the node's state)
			  name: nano
			  state: latest # this is the "state"
```
### Run the Playbook:
```shell
$ ansible-playbook iluvnano.yml

PLAY [iluvnano] *******

TASK [Gathering Facts] ********
ok: [69.69.69.6]
ok: [69.69.69.9]

TASK [ensure nano is there] ********
changed: [69.69.69.6]
changed: [69.69.69.9]

PLAY RECAP ********
69.69.69.6             : ok=2  changed=1  unreachable=0  failed=0  skipped=0
	rescued=0  ignored=0
69.69.69.9             : ok=2  changed=1  unreachable=0  failed=0  skipped=0
	rescued=0  ignored=0
$
```
*Ansible will not make a change if it is already in place* (for example, if we run this command again w/o changing the playbook)

> [!links]
> [Ansible: Network Chuck](https://www.youtube.com/watch?v=5hycyr-8EKs&ab_channel=NetworkChuck)
> [Ansible Documentation](https://docs.ansible.com/ansible/latest/index.html)


