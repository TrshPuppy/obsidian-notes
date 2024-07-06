
# Boot Integrity
Getting malicious access to the boot process of a device is a perfect infection point. This is what root kits do when they compromise a machine's kernel. Rootkits gain *the same rights as the operating system* at this level. So, protecting the boot process *is very important*.

In order to maintain and verify boot integrity, the boot process is  done in two parts. First, the *secure boot process* (starting in the hardware), and then the *trusted boot process*.
## Secure Boot Process
Security in the boot process depends on the **Hardware root of trust**. This is where the trust of a machine begins, and there are two types:
### Hardware Boot Protection
#### Trusted Platform Module
**TPM**: A piece of hardware that's either installed on the motherboard or comes as part of the motherboard. It helps *with encryption processes* used by apps in the OS. It also has *persistent memory* so it can save the unique keys which are burned into it at production. We can reference this as a *unique value* that another device won't have (unique identifier of the device).

Also has *versatile memory* used for storing new encryption keys and configuration info. All of this is *password protected* and brute-forcing the password is *prevented through anti-brute force* tech.
#### Hardware Security Module
**HSM:**
### Software Boot Protection
An example of software which is used to protect and secure the boot process is **UEFI BIOS Secure Boot**. This is part of the U[EFI specification], so any device w/ a UEFI BIOS can use secure boot.
#### BIOS Protections
The BIOS includes the *manufacturer's public key* and there is a *digital signature check* whenever the BIOS undergoes an *update*. This means someone can't try to update it w/ a different update *or change the update in any malicious way*. The BIOS also *prevents unauthorized writes* to flash memory.

BIOS Secure boot also verifies the bootloader by *checking its digital signature against that of the manufacturer*. The bootloader must be *signed w/ a trusted certificate* or a manually-approved digital signature. This all *prevents any malicious changes to the bootloader*. 
## Trusted Boot Process
The bootloader (which we know *hasn't been tampered with*) verifies the digital signature of the *OS kernel*. If the kernel is corrupted, the entire boot process will *stop*. Once the kernel has been verified, it will verify *all the other startup components* including boot drivers, startup files, etc..
### ELAM
**Early Launch Anti-Malware**: Just before the OS starts loading up any hardware drivers, it starts the ELAM process. This process *checks every driver to see if it's trusted*. Each driver has a *digital signature*, and if it can't pass the check of its signature, then Windows, specifically, won't load an un-trusted driver.
### Measured Boot
Once the drivers are loaded via ELAM, the device moves on to the measured boot process. This allows admins to measure whether *anything has changed about the computer*. Some measurements which are taken and compared (before and after) include *a hash of the firmware, boot drivers, and everything loaded during secure boot and trusted boot* (stored by UEFI systems). These hashes are stored in the TPM to be used in *Remote Attestation.*
#### Remote Attestation
Once all of the hashes have been generated and stored in the TPM, the device serves as a management server (called the *Attestation Server*) with a *verification report* showing the results of all the hashes and the boot process. If anything seems off or has changed, then *Admins can choose to turn the system off or disable it.*

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=XqtqbJ0nMVY&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=103)