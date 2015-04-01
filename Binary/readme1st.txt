If you plan to use EFI based VM's:

1) Make sure, Tsugumi is properly unloaded (using remove.cmd) before doing next step.
2) Make copy of VBoxEFI64.fd in VirtualBox directory.
3) Replace VBoxEFI64.fd in VirtualBox directory with it patched version from this data directory. 
4) Use hidevm_efiahci (AHCI controller mode) or hidevm_efiide (IDE controller mode) for your EFI VM.
5) Load Tsugumi (using install.cmd).
6) Run VirtualBox.

please see comments in install.cmd, remove.cmd before running them.