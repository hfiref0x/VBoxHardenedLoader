# Installation guide

Step by step guide for VM detection mitigation configuring using VirtualBox x64 Hardened loader v2.

Note: Minimum required VirtualBox version is 6.1.2

Contents:

 * Installing VirtualBox
 * Creating VM with required settings
 * Using batch script to apply fake VM system information
 * Loading monitoring driver for load-in-memory VM dll patch
 * Stopping monitoring driver
 * Warning: VirtualBox Additions 
 * Appendix A: Using EFI VM
 * Appendix B: Uninstalling VirtualBox loader
 * Appendix C: Updating VirtualBox
  

### Step 1. Installing VirtualBox


1. Download VirtualBox from official site (https://www.virtualbox.org/wiki/Downloads). 
2. Do clean installation of latest VirtualBox. 
   * Clean mean - you must firstly uninstall any other versions of VirtualBox and reboot Windows to complete uninstallation. This ensures that no old VirtualBox files will left in system memory and on disk. Unfortunately VirtualBox setup sometimes can't do complete removal without reboot, so do reboot after uninstall.
3. Start installation and select VirtualBox components to install as shown on fugure below.
<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/1_install.png" />

### Step 2. Creating VM with required setting

In this example we are installing and configuring VirtualBox on x64 PC running full patch Windows 8.1.

Create a new virtual machine (in this example it will be named "vm0") and configure it in the following way:

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/2_createvm.png" />

Note: 2048 Mb is not requirement, you can adjust or lower this value as you want, but keep in mind - some lame malware attempt to detect VM by available physical memory size, and if its too low - use it as VM detection flag.

Setup Virtual disk

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/3_createhdd.png" />

Note: 64 Gb is not requirement and just used as example, however yet again some lame malware attempt to detect VM by hard disk size, so give it reasonable size (>32 Gb).

After VM (vm0 is our case) created, open it setting and do some changes.

#### System

On "Motherboard" tab ensure Enable I/O APIC is turned on. If you plan to use EFI please read Appendix A: Using EFI VM.

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/4_settings_mb.png" />

On "Processor" tab ensure PAE/NX enabled. Also note that your VM must have at least TWO CPUs because again number of processors used by malware to determinate VM execution. So give VM at minimum two processors.

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/5_settings_cpu.png" />

On "Acceleration" tab set Paravirtualization Interface to "Legacy" and enable VT-x/Nested Paging. The "Default" paravirtualization interface give VM ability to detect VirtualBox hypervisor by "hypervisor present bit" and hypervisor name via cpuid instruction. Switching paravirtualization interface to "Legacy" effectively turns off these malware vm-detect friendly features.

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/6_settings_accel.png" />

#### Display

On "Screen" tab disable 3D/2D Acceleration.

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/7_display.png" />

#### Storage

Storage configuration would be looking like that

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/8_storage.png" />

You can use IDE controller instead of SATA, but we will be assuming that you use default SATA next.

#### Network

Enable NAT for virtual machine, so you can use FTP like programs to communicate with it and machine will have access to internet (if you have it).

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/9_network.png" />

Once all settings set, press OK button.

### Step 3. Using batch script to apply fake VM system information

Close VirtualBox.

Save https://github.com/hfiref0x/VBoxHardenedLoader/tree/master/Binary folder to your PC, for example we will save it as C:\VBoxLdr and use this directory next in examples. Open command line prompt (Win+R, type cmd, press Enter). Change current directory to VBoxLdr\data directory (type cd C:\VBoxLdr\data, press Enter)

Now important part. Select script to work with it next depending on your VM configuration.

> hidevm_ahci is for VM with SATA/AHCI controller and classical BIOS

> hidevm_ide is for VM with IDE controller and classical BIOS

> hidevm_efiahci is for VM with SATA/AHCI controller and EFI

> hidevm_efiide is for VM with IDE controller and EFI

If you plan to use EFI VM see "Appendix A: Using EFI VM" before doing any further steps.

In our example we created VM without EFI support and with SATA/AHCI controller so we will use hidevm_ahci script. Open it with notepad and change the following lines: 

> set vboxman="C:\Program Files\Oracle\VirtualBox\vboxmanage.exe"
> 
> set vmscfgdir=D:\Virtual\VBOX\Settings\

Here you see two variables used as filepaths below in script, change them to actual locations.

Depending on where your VirtualBox installed place correct path to vboxmanage.exe in vboxman variable. Depending on where you saved Binary folder change it for vmscfgdir variable.

In our example we will leave vboxman as is, because we didn't changed VirtualBox installation path and change D:\Virtual\VBOX\Settings\ to C:\VBoxLdr\data so both lines will look like 

> set vboxman="C:\Program Files\Oracle\VirtualBox\vboxmanage.exe"
>
> set vmscfgdir=C:\VBoxLdr\data\

Note the backslash at the end of vmscfgdir.

After that save script changes.

Type it in comand line prompt and add your VM name as parameter, e.g. in our case: 

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/10_script.png" />

Run it by pressing Enter. This will setup additional configuration for your VM.

Do not run any VM, as it is not ready yet.

### Step 4. Loading monitoring driver for load-in-memory VM dll patch

Close VirtualBox if it opened. 

Open elevated command line prompt. Run cmd.exe as admin and switch current directory to C:\VBoxLdr (or where you saved Binary folder). Use loader.exe to start monitoring, type as below on screenshot:

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/11_loader_before.png" />

Upon successful execution you will see something like that:

<img src="https://raw.githubusercontent.com/hfiref0x/VBoxHardenedLoader/master/Binary/help/12_loader_after.png" />

Done, monitoring driver loaded and configured. You will have to repeat this (and only) step each time you boot Windows, because monitoring driver will be unloaded automatically upon system shutdown/reboot.

### Step 5. Stopping monitoring driver.

Close VirtualBox if it opened.

Open elevated command line prompt, navigate to VBoxLdr folder and run loader with /s switch, e.g. loader.exe /s. To reenable monitoring just re-run loader without parameters elevated (as admin). Monitoring driver will be unloaded at Windows shutdown or reboot. To start it again repeat step 4.

## Warning: VirtualBox Additions

Do not install VirtualBox Additions! This will ruin everything and there is NO workaround for this.

### Appendix A: Using EFI VM

Configure VM to use alternative EFI ROM with help of VBoxManage.

*vboxmanage setextradata vmname "VBoxInternal/Devices/efi/0/Config/EfiRom" full_path_to_your_patched_efirom*

For example, if you are using VirtualBox 6.1.2 then

*vboxmanage setextradata vm01 "VBoxInternal/Devices/efi/0/Config/EfiRom" C:\VBoxLdr\data\efi_amd64_fixed_6.1.2*

To automate this you can add the following string to EFI vm configuration scripts

*%vboxman% setextradata "%1" "VBoxInternal/Devices/efi/0/Config/EfiRom" full_path_to_your_patched_efirom*

Note: configuration scripts hidevm_efiahci/hidevm_efiide already has this setting set.

### Appendix B: Uninstalling VirtualBox loader

If monitoring driver loaded - reboot Windows. Delete VBoxLdr folder.

### Appendix C: Updating VirtualBox

Scenario: you decided update VirtualBox without clean reinstall and rebooting your PC. Will the loader work with new version? Yes it will, but you have to re-run loader.exe in elevated command prompt to update patch information for new version of VirtualBox dynamic link library VBoxDD.dll. Basically you need to repeat Step 4.
