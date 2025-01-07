
# `locate` Command
Init.

The `locate` command in Linux can be used to find *specific files* on a Linux machine. It uses a database (default path: `/var/lib/plocate/plocate.db`) to keep track of files on the system and to report back to the invoking user what sfails exist based on their inquiry.
## Use
### Basic
```bash
┌──(trshpuppy㉿kali)-[~]
└─$ locate universal        
/home/trshpuppy/oscp/universal.ovpn
/usr/lib/python3/dist-packages/chardet/universaldetector.py
/usr/lib/python3/dist-packages/chardet/__pycache__/universaldetector.cpython-311.pyc
/usr/lib/python3/dist-packages/jedi/third_party/typeshed/third_party/2and3/chardet/universaldetector.pyi
/usr/lib/python3/dist-packages/win32com-stubs/universal.pyi
/usr/lib/ruby/vendor_ruby/rchardet/universaldetector.rb
/usr/share/icons/Flat-Remix-Blue-Dark/apps/scalable/cs-universal-access.svg
/usr/share/icons/Windows-10-Icons/256x256/apps/cs-universal-access.png
/usr/share/metasploit-framework/modules/exploits/windows/brightstor/universal_agent.rb
/usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/rasn1-0.13.1/lib/rasn1/types/universal_string.rb
/usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/rubyzip-2.3.2/lib/zip/extra_field/universal_time.rb
/usr/share/rubygems-integration/all/gems/rubyzip-2.3.2/lib/zip/extra_field/universal_time.rb
/usr/share/sqlmap/thirdparty/chardet/universaldetector.py
/usr/share/sqlmap/thirdparty/chardet/__pycache__/universaldetector.cpython-311.pyc
/usr/share/windows-resources/wce/wce-universal.exe
```
### Updating the database
To update the database `locate` is using, use the [updatedb](updatedb.md) command. 
### Searching a specific database
To search a specific database (rather than the defualt one which stores results for the entire filesystem) use the `-d` flag with the path to the database you want.

For example, I made this database using the `updatedb` command like so:
```bash
┌──(trshpuppy㉿kali)-[~]
└─$ updatedb -o test oscp/ 
```
This create a plocate database with every file in the `oscp/` directory. So, the results of searching for a file called `universal` in the filepaths stored in the `test` directory looks like this:
```bash
┌──(trshpuppy㉿kali)-[~]
└─$ locate universal -d test
/home/trshpuppy/oscp/universal.ovpn
```

> [!Resources]
> - `man locate`
> - `man updatedb`