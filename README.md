# uefi-cert-research
UEFI certificate research 

This script will search one or more files for x509 data which is used to validate uefi drivers and bootloaders

`sudo apt install -y python3-cryptography` 

On a typical linux machine you can run the following:

`python3 ./find_cert.py /sys/firmware/efi/efivars/*`

which will show you the certificates, including possibly many expired ones.

You may need to escalate with your system vendor to ensure they are providing non-expired certificates as this may impact your ability to receive code updates or proper secure-boot support for future releases.

You can always disable sb validation with `mokutil --ignore-db` or similar commands, including: `mokutil --disable-validation`

You should use caution when working with any of your secure boot options.
