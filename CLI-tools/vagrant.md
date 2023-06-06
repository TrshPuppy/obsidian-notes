
# Hashicorp Vagrant
Hashicorp Vagrant is software which you can use in the CLI to manage and automate managing virtual machines.

## Basics:
### Base Box:
A base box is a virtual box with the bare minimum that Vagrant needs to run. Usually this includes (for linux) a package manager, SSH with a user, and (for VirtualBox) VBox guest additions.

#### Creating a base box:
Specific for each VM provider (VirtualBox, VM Ware, Docker, etc.),

##### Disk Space:
*Make sure the base box has enough disk space!* For example, a base box for VirtualBox should be set w/ a dynamically resizing drive w/ a large max size.

Doing this will cause the base box to start with a small foot print on the drive which will dynamically grow to the max size as you use it.

##### Memory:
The base box usually does fine with 512MB of memory. Giving it too much can cause issuses. The memory allocation can always be increased in the Vagrantfile.

##### Peripherals:
The base box does not require peripherals, so they should be disabled, including audio, USB controllers, etc, (and can be added later in the Vagrantfile).
