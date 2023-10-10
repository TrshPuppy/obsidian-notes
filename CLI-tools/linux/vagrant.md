
# Hashicorp Vagrant
Hashicorp Vagrant is software which you can use in the CLI to manage and automate managing virtual machines.
## Base Box
A base box is a virtual box with the bare minimum that Vagrant needs to run. Usually this includes (for linux) a package manager, SSH with a user, and (for VirtualBox) VBox guest additions.
### Creating a base box
Specific for each VM provider (VirtualBox, VM Ware, Docker, etc.),
#### Disk Space
*Make sure the base box has enough disk space!* For example, a base box for VirtualBox should be set w/ a dynamically resizing drive w/ a large max size.

Doing this will cause the base box to start with a small foot print on the drive which will dynamically grow to the max size as you use it.
#### Memory
The base box usually does fine with 512MB of memory. Giving it too much can cause issues. The memory allocation can always be increased in the Vagrantfile.
#### Peripherals
The base box does not require peripherals, so they should be disabled, including audio, USB controllers, etc, (and can be added later in the Vagrantfile).
### Default Settings
These settings should be applied so Vagrant can work 'out of box.'
#### Vagrant User
Vagrant expects a 'vagrant' user which will be used to SSH into the base box. This user need to be setup w/ an [insecure keypair](https://github.com/hashicorp/vagrant/tree/main/keys).

The vagrant user should belong to the 'vagrant' group and the password should be set to 'vagrant' (for manual login).
#### SSH Access
Place the public key into `~/.ssh/authorized_keys`. Make sure the file has `0700` permissions and the key has `0600` [permissions](/nested-repos/PNPT-study-guide/practical-ethical-hacking/kali-linux/file-permissions.md).

*Note* that when Vagrant boots a box, the insecure keypair will be replaced w/ a randomly generated pair while the box is running.

*SSH Tweaks:* To help make SSH speedy when the machine (or your machine) is not connected to the internet, set the `UseDNS` configuration to `no` in the SSH server config. This prevents the client from doing a reverse DNS lookup (which takes longer).
##### Passwordless sudo
*IMPORRTANT:* Vagrant expects that the default SSH user has 'passwordless sudo' configured so it can configure networks, mount folders, etc.. You also should make sure the *base box has sudo installed* b/c some distros don't.

To configure passwordless sudo, use `visudo` to edit the sudoers file:
```bash
vagrant ALL=(ALL) NOPASSWD: ALL
```

*Additionally:* Make sure there is no `requiretty` line in the file. Remove if there is one.
### Packaging the Base Box
Packaging the box into a `box` file is different depending on the provider.
### Testing the Base Box
You can test the base box using the following commands:
```bash
vagrant box add --name <your box> /path/to/new.box
...
vagrant init <your box>
...
vagrant up # NOTE: give 'vagrant up' the provider you're using w/ '--provider'
```
If `vagrant up` succeeded than the box is successful!
## Box File
The `.box` file is a tarball (`tar`, `tar.gz`, `zip`) which has all the information for a provider to a launch a Vagrant machine.
### Components
There are four components which make up the `.box` file. If you were to extract a box and look at it, it should look something like this:
```
# contents of the hashicorp/bionic64 box
# ref: https://app.vagrantup.com/hashicorp/boxes/bionic64
$ ls hashicorp_bionic_box
Vagrantfile                      metadata.json
box.ovf							 ubuntu-18.04-amd64-disk001.vmdk
```
1. VM Artifacts (*required*): This includes the VM image and other artifacts (in whatever format is accepted by the provider). For example, VirtualBox requires a `.ofv` or `.vmdk` file.
2. `metadata.json` (*required*): Contains a map w/ the information about the box and target provider.
3. `info.json`: JSON file which includes additional info on the box. This info is displayed when a user runs `vagrant box list -i`
4. Vagrantfile: Embedded in the box and provides defauls for the users of the box.
### `metadata.json`
There should only be one of these per box. It should contain (at the very least) the `provider` key w/ the provider the box is for. This is used to verify the provider.
```json
{
	"provider": "virtualbox"
}
```
## Box Repository
A box repository is a collection of vagrant boxes (`.box` files) and their metadata. It is usually kept on the local filesystem or in a service like Vagrantcloud.
### Components
#### Box Catalog Metadata
This is an optional component that enables versioning and updating multiple providers from a single file. It's a JSON file structured like this:
```json
{
  "name": "hashicorp/bionic64",
  "description": "This box contains Ubuntu 18.04 LTS 64-bit.",
  "versions": [
    {
      "version": "0.1.0",
      "providers": [
        {
          "name": "virtualbox",
          "url": "http://example.com/bionic64_010_virtualbox.box",
          "checksum_type": "sha1",
          "checksum": "foo"
        }
      ]
    }
  ]
}
```
>	[Hashicorp](https://developer.hashicorp.com/vagrant/docs/boxes/box_repository)

This JSON can be passed using `varant box add` or via a file path. Vagrant will use it to install the correct version of the box.

The `url` key key can also be set to a local file path. If there are multiple providers, Vagrant will ask which one you want to use.
## Provisioning
[Provisioning](https://developer.hashicorp.com/vagrant/docs/provisioning) with vagrant allows you to install software automatically to vagrant boxes.

> [!Resources]
> - [Vagrant Docs](https://developer.hashicorp.com/vagrant/docs/boxes/base)
> - [Vagrant GitHub: Insecure key pairs](https://github.com/hashicorp/vagrant/tree/main/keys)

