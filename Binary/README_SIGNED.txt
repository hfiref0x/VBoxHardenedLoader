Installation and use of signed loader.

1) Install supported VirtualBox version.
 
Loader v1.8+ support VirtualBox versions starting from 5.1, earlier versions may not be supported

2) Create a new vm with the following settings.

System->Mortherboard
Chipset = PIIX3
Pointing Device = PS/2 Mouse
Extended features: [+]Enabled I/O APIC, ([+]Enable EFI, see EFI note)

System->Processor
Processors = set at minumum 2
Extended features: [+]Enable PAE/NX

System->Acceleration (some of these settings may be unavailable in earlier VBox versions)
Paravirtualization Interface = set Legacy
Hardware Virtualization = [+]Enable VT-x/AMD-V, [+]Enable Nested Paging

Display->Screen
Acceleration = [-]Enable 3D Acceleration, [-]Enable 2D Video Acceleration

Storage
Controller: SATA or IDE

Network
Enable NAT for adapter

Close virtualbox, do not start machine.

If you selected Enable EFI see step (5) before doing step (3)

3) Depending on settings use following batch scripts

if you selected EFI and IDE controller
hidevm_efiide.cmd YOURMACHINENAME e.g. hidevm_efiahci.cmd win10

if you selected EFI and SATA controller
hidevm_efiahci.cmd YOURMACHINENAME e.g. hidevm_efiahci.cmd win10

if you selected IDE controller without EFI
hidevm_ide.cmd YOURMACHINENAME e.g. hidevm_ide.cmd win7

if your selected SATA controller without EFI
hidevm_ahci.cmd YOURMACHINENAME e.g. hidevm_ahci.cmd win7

Before running scripts make sure vmscfgdir variable inside points to directory where all required files available (copy contents of Binary folder somewhere, for example D:\Virtual\VBOX\Settings, where VBox is folder for virtual machines).

4) Install Tsugumi monitor driver (perform real time VirtualBox memory patch).

Make sure Tsugumi.sys driver file is in the same directory as loader.exe

Run from elevated command prompt

loader.exe

loader will generate patch data for your VirtualBox installed version, write it to the registry, load monitoring driver (using Service Control Manager) and notify driver about new data. That all, now you can run your VM.

If you want to stop real time patching: run loader elevated with command line parameter /s (e.g. loader.exe /s). This will disable Tsugumi monitoring and allow you to use VM without dlls patch. Run loader again to start monitoring (see above).

DO NOT INSTALL VBOX ADDITIONS, this will ruin everything and there is NO WORKAROUND for this.

Note: Once installed by loader Tsugumi.sys will accept net/sc commands, e.g. you can unload it with "net stop tsugumi" or load it again without using loader.

5) EFI Note

If you plan to use EFI based VM's:

a) Make sure, Tsugumi is not loaded before doing next step.
b) Make copy of VBoxEFI64.fd in VirtualBox directory.
c) Replace VBoxEFI64.fd in VirtualBox directory with it patched version from this data directory. 
d) Use hidevm_efiahci (AHCI controller mode) or hidevm_efiide (IDE controller mode) for your EFI VM.
e) Load Tsugumi (see step (4)).
f) Run VirtualBox.

please see comments in install.cmd, loader.cmd before running them.

Last update
01/Feb/17
