
# Torrent Files
Torrent files (`.torrent`) are files which contain the locations & infor of computers which have downloaded the same resource, or parts of the same resource. 

They're used to help download large files from multiple sources (instead of downloading them from one source which can take a long time and increases traffic for whoever is hosting the file/s).

Downloading content from multiple sources (called "seeders") is much faster than downloading the traditional way from one source.

## BitTorrent Protocol:
In order to use a torrent file to locate and download resources, you need a torrent client.

A torrent client is software which can read a `.torrent` file and and communicating with seeder machines to download the content to your computer.

The BitTorrent client will look for a `tracker` which is specified in the file. The `tracker` is the address for a special server who maintains a list of seeders who have a complete copy of the target file to download.

The BitTorrent protocol breaks the target file into chunks and helps the client retrieve those chunks from seeders.

Once you've downloaded a torrent file using the BitTorrent client, you can opt-in to becoming a seeder and leaving the client running so others can download it from you.

## Security:
### IP Address:
When you use torrent to download content, your [IP address](/networking/OSI/IP-addresses.md) is visible to everyone who is or will also download the content.

You can use a [VPN](/networking/routing/VPN.md) to help protect yourself from this.

### Adware & Malware:
Some BitTorrent clients can download adware and malware on your system when you use them.


> [!Resources:]
> - [Tech Radar: What is a torrent](https://www.techradar.com/vpn/what-is-a-torrent)

> [!My previous notes (linked in text)]
> - [IP Addresses](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/OSI/IP-addresses.md)
> - [VPN](https://github.com/TrshPuppy/obsidian-notes/blob/main/networking/routing/VPN.md) 
