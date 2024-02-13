
# Using Checksums
Checksums are usually hashes of a file used to identify and uniquely represent it. If anything in a file changes, the hash/ checksums of the file before and after the change will be different.

Because of this, checksums can be used to verify the integrity of a shared or downloaded file.

*For example* you can generate checksums of your file backups so you can verify they haven't been tampered with when you access them later.
## Algorithms:
The two most common algorithms used in checksums is SHA and MD5. When you verify a checksum, you have to be sure to use the same algorithm to generate the checksum, or the two hashes will be different.
## Generating Checksums:
### Linux:
Linux has some command line tools to generate checksums and hashes for files.
#### `md5sum`:
Usage:
```bash
┌──(hakcypuppy㉿kali)-[~]                                                 
└─$ md5sum --help                                                             
Usage: md5sum [OPTION]... [FILE]...                                           
Print or check MD5 (128-bit) checksums.                                       
  
With no FILE, or when FILE is -, read standard input.                         
  -b, --binary          read in binary mode                                   
  -c, --check           read checksums from the FILEs and check them          
      --tag             create a BSD-style checksum                           
  -t, --text            read in text mode (default)                           
  -z, --zero            end each output line with NUL, not newline,           
						and disable file name escaping                      
 
The following five options are useful only when verifying checksums:          
      --ignore-missing  don't fail or report status for missing files         
      --quiet           don't print OK for each successfully verified file    
      --status          don't output anything, status code shows success      
      --strict          exit non-zero for improperly formatted checksum lines 
  -w, --warn            warn about improperly formatted checksum lines          
      --help            display this help and exit                               
      --version         output version information and exit 

The sums are computed as described in RFC 1321.
When checking, the input should be a former output of this program.
The default mode is to print a line with: checksum, a space,
a character indicating input mode ('*' for binary, ' ' for text
or where binary is insignificant), and name for each FILE.
```

#### `sha512sum`:
Usage:
```bash
# The --help for sha512sum is identical to md5sum --help
```

## Verifying Checksums:
### Linux (ex using [OWASP Amass](/cybersecurity/tools/amass.md)):
We're going to verify the checksum of this OWASP Amass download before downloading it *so we know it's safe and coming from the source we think it's coming from ([OWASP](cybersecurity/resources/OWASP.md))*.

#### 1. Go to GitHub releases page of OWASP-Amass tool:
`https://github.com/owasp-amass/amass/releases/tag/v3.23.3`
Click to `download amass_checksums.txt`

#### 2. Go to Downloads folder via terminal:
Cat the file to see the checksums for each download:
```bash
┌──(hakcypuppy㉿kali)-[~/Downloads]
└─$ cat amass_checksums.txt 
...bc8ae1bab8713ec0adb7c4c01616f37d7cfa395bfc94a0dd2  amass_Darwin_amd64.zip
...1e5017d232deb701e195e05f7a7c0a98b176325dfc2774a30  amass_Windows_amd64.zip
...c99e32c2b930207c539886f8277794f7b25edbc8ecba0930e  amass_Freebsd_amd64.zip
...3dfb416099fb0452e2b4b4da5170f0b23cd3b812df2e9319c  amass_Linux_amd64.zip
...
```

#### 3. Isolate the checksum of your download:
```bash
cat amass_checksums.txt | grep "amass_Linux_amd64.zip" | cut -d " " -f 1 > checksum.txt
```

#### 4. Compare the checksum to the one you generate using the download file:
(Assuming the unzipped download is also in your `Downloads` folder):

If you don't know what algorithm was used to make the checksum, there are ways to figure it out:

##### MD5:
The [MD5](computers/concepts/cryptography/hashing.md#MD5) Algorithm generates a 128 bit hash represented by 32 hexadecimal characters.

##### SHA512:
The [SHA512](computers/concepts/cryptography/hashing.md#SHA-2) is a variant of SHA-2. It produces a hash with 128 characters.

##### Verifying the two checksums:
```bash
# Using MD5sum first:
┌──(hakcypuppy㉿kali)-[~/Downloads]
└─$ md5sum amass_Linux_amd64.zip > md5.txt

┌──(hakcypuppy㉿kali)-[~/Downloads]
└─$ cat md5.txt 
bfbb46361ac3d4df30a9c07f2ce45a70  amass_Linux_amd64.zip
# Using SHA512sum:
┌──(hakcypuppy㉿kali)-[~/Downloads]
└─$ sha512sum amass_Linux_amd64.zip > sha.txt

┌──(hakcypuppy㉿kali)-[~/Downloads]
└─$ cat sha.txt
b1046b3b08e1697ecd08310b0f52d5abd185aae1a594025feb58a49a2a85fd7eff5928cc928ca6ebc7ba3c3c44ad9f02afa51587ea3a3a1f86bcb3820c618d94  amass_Linux_amd64.zip
#  Neither of them match...
#  Fortunately there is a sha256sum command:
┌──(hakcypuppy㉿kali)-[~/Downloads]
└─$ sha256sum amass_Linux_amd64.zip > sha256.txt

┌──(hakcypuppy㉿kali)-[~/Downloads]
└─$ cat sha256.txt           
2b5afb8a567d9703dfb416099fb0452e2b4b4da5170f0b23cd3b812df2e9319c  amass_Linux_amd64.zip
```
 

> [!Resources:]
> - [Infosec Scout: Identify MD5 Hash](https://infosecscout.com/identify-md5-hash/)
> - [Wikipedia: SHA-2](https://en.wikipedia.org/wiki/SHA-2)
> - [Medium: Cryptography: Explaining SHA-512](https://medium.com/@zaid960928/cryptography-explaining-sha-512-ad896365a0c1)

