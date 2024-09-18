
# Registry (Windows)
Init.
The registry is the *primary configuration database* for Windows machines. Nearly everything can be configured from the registry. When new applications are installed, it's difficult to know *what it changes in the registry*. There are tools which you can use to check the state of the registry before and after installing a new program so you can see if anything changed.
## Security related Registry changes
The registry has some *important security settings.* For example,  the registry can be used to *configure permissions* for files and services. Additionally, *vulnerable apps and services can be enabled/ disabled* from the registry. For example, [SMBv1](../../../networking/protocols/SMB.md#SMBv1) (a vulnerable version of SMB) can be enabled in the registry, making the device vulnerable to exploits which take advantage of it.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=KxiPfczekFA&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=106)