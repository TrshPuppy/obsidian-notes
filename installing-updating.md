
# [Package Management in Linux](/computers/linux/package-management.md)

## apt
> [!My previous notes]
> - [Linux Package Management](https://github.com/TrshPuppy/obsidian-notes/blob/main/computers/linux/package-managment.md)

## Pimp my Kali:
[Pimp my Kali](https://github.com/Dewalt-arch/pimpmykali) is an open source tool you can find on GitHub. Using open source tools can be risky, so a good way to check if a tool is legitimate and safe to use is to look at how active the repo is, i.e. how many stars it has, how many watching, when it was last updated, etc..

Pimp my Kali is meant to fix issues that Vanilla Kali has. It can be installed/ downloaded using `git` VCS by using `git clone` to clone the repo into your own local directory (should go into your `/opt` directory).

### Running PMK:
Once you have the repo cloned into `/opt`, `cd` into it and use `sudo ./pimpmykali.sh` to run the tool.

When you run PMK for the first time (using the `-N` option inside a new Kali VM) it will update/ install/ uninstall packages in your Vanilla Kali which are commonly broken/ missing/ outdated, etc.

