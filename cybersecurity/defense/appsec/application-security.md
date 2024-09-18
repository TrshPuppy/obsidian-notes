
# Application Security
Secure coding concepts are meant to be involved in the development process of software so that it's coded in a secure way. Either way, software is still going to have bugs and vulnerabilities when its released and in prod.
## Secure Coding Considerations
### Input Validation
#### Normalization
Checking and correcting data input.
### Dynamic Analysis/ Fuzzing
Will find what you missed in input fields by trying a bunch of different combos on them. Sending random input into an application. Also called fault injection, robustness testing, syntax testing, negative testing. Meant to look for something out of the ordinary to happen like an error or the application crashing.
#### Fuzzing Engines and Frameworks
Platform specific, lang specific automated fuzzing frameworks. Very time and processor/ resource heavy. Have to do many iterations with many inputs and randomized inputs. Use *high probability tests* to try to cut down on the time and resources it took.
##### CERT
**Carnegie Mellon Computer Emergency Response Team:** developed a basic fuzzing framework ([BFF](https://insights.sei.cmu.edu/library/cert-bff/)).
### Secure Cookies
Cookies in general are used to keep track of information temporarily, like log in and session info. *Secure Cookies* are cookies with a secure attribute set on them. This tells the browser to (only send them over [HTTPS](../../../../www/HTTPS.md)).

Even though these cookies are "secure" they *should not be used to store private information*.
### HTTP Secure Headers
Added to the web server configuration and allows it to restrict the browser and what it's allowed to do. Tells the user's browser to allow or not allow certain tasks while the app is in use. For example, there are [HTTP](../../../../www/HTTP.md) headers which tell the browser to (only use HTTPS). Can also set headers so the browser is only allowed to use scripts, stylesheets, images, etc. from the local site which helps to prevent [XSS](../../../../cybersecurity/TTPs/exploitation/injection/XSS.md).
### Code Signing
When an application is deployed, we want a way to tell if the executable *has been tampered with* or is legit at all. One way to do this is with code signing. In addition to telling us if an app has been modified, code signing also confirms *the specific developer who wrote it.*
#### [Asymmetric Encryption](../../../../computers/concepts/cryptography/asymmetric-encryption.md)
Code signing uses asymmetric encryption to create a digital signature. To sign code, a trusted certificate authority (CA) signs *the developer's public key*. Then, the developer *signs with their private key*.
### Allow/ Deny Lists
Allow and deny lists can be set on a device by an admin. These are *security policies* which control what apps can and can't execute on the machine. Nothing runs unless it's allowed + nothing on the deny list can be executed.

Decisions are made in the [operating system](../../../computers/concepts/operating-system.md) because the lists are often *built into the OS management*. 
#### Application Hash
Only allow applications with this unique [hash](../../../computers/concepts/cryptography/hashing.md). Hashing also protects against modification since the hash changes w/ modification of the file.
#### Certificate
Only allow applications which have been digitally signed by certain publishers.
#### Path
Only allow applications in specific folders to run.
#### Network Zone
Only allow applications running w/i a specific network and/ or server.
### Static App Security Testing: 
![SAST](appsec/appsec.md#SAST)
### Dynamic App Security Testing
![DAST](appsec/appsec.md#DAST)


> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=CwtHoL1CQ68&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=105)