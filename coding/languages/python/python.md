
# Python coding language
Init.
## Tips/ Tricks:
### venv
#### Python Venv
> [!Resources: venv]
> - [Python: venv](https://docs.python.org/3/library/venv.html)
> - [Python Land: How to create... venv](https://python.land/virtual-environments/virtualenv)

Python venv is essentially a tiny VM where you can do all of your dev work on python. It creats a virtual environment for needed dependencies etc.. You can destroy it once you're done, allowing you to avoid installing unneeded BS on your machine.

After installing venv, you can set it up in your working directory like this:
```bash
┌──(hakcypuppy㉿kali)-[~/blue]
└─$ python3 -m venv venv 
┌──(hakcypuppy㉿kali)-[~/blue]
└─$ ls 
blue.findings.txt  blue.msfconsole.smb.versioning.txt  blue.txt  eb.py  enum4linux.blue.txt  mysmb.py  __pycache__  venv
┌──(hakcypuppy㉿kali)-[~/blue]
└─$ source venv/bin/activate
┌──(venv)(hakcypuppy㉿kali)-[~/blue]   # <---- now you're in the virtual env.
└─$ 
```
##### Usage
To see all the flags you can give to venv, type `python3 -m venv -h`.
##### Delete a venv
Before you can delete the venv, you *have to deactivate it*. To deactivate it you simply type `deactivate` while in the venv. You can then *clear the contents of the venv directory* using `python3 -m --clear <name of venv dir>`.

Now, to remove the venv just remove the `venv` directory:
```bash
ls                                                              
AutoBlue-MS17-010                   blue.txt             mysmb.py
blue.findings.txt                   eb.py                __pycache__
blue.msfconsole.smb.versioning.txt  enum4linux.blue.txt  venv # <--------
# 
rm -r venv
```
This will change depending on if you created the vent using `python -m venv` versus Virtualenv.
#### pipenv
`pipenv` is another choice for making a python virtual env. 


