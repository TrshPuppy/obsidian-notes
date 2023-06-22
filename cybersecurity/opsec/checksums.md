
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
We're going to verify the checksum of this OWASP Amass download before downloading it *so we know it's safe and coming from the source we think it's coming from ([OWASP](/cybersecurity/literature/OWASP.md))*.

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

```
```