rem @echo off

rem EFI/IDE mode
rem This script is for use with VBoxHardenedLoader v2+

rem vboxman is the full path to the vboxmanage executable
rem vmscfgdir is the path to directory that keeps vbox custom configuration data (bioses, tables etc)

set vboxman="C:\Program Files\Oracle\VirtualBox\vboxmanage.exe"
set vmscfgdir=D:\Virtual\VBOX\Settings\
set /p VM="Input Name of VM: "

%vboxman% setextradata "%VM%" "VBoxInternal/CPUM/EnableHVP" 0
%vboxman% setextradata "%VM%" "VBoxInternal/TM/TSCMode" RealTSCOffset

%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBIOSVendor" "Apple Inc."
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBIOSVersion" "MB52.88Z.0088.B05.0904162222"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBIOSReleaseDate" "08/10/13"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBIOSReleaseMajor" "5"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBIOSReleaseMinor" "9"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBIOSFirmwareMajor" "1"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBIOSFirmwareMinor" "0"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiSystemVendor" "Apple Inc."
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiSystemProduct" "MacBook5,2"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiSystemVersion" "1.0"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiSystemSerial" "CSN12345678901234567"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiSystemSKU" "FM550EA#ACB"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiSystemFamily" "Ultrabook"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiSystemUuid" "B5FA3000-9403-81E0-3ADA-F46D045CB676"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBoardVendor" "Apple Inc."
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBoardProduct" "Mac-F22788AA"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBoardVersion" "3.0"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBoardSerial" "BSN12345678901234567"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBoardAssetTag" "Base Board Asset Tag#"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBoardLocInChass" "Board Loc In"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiBoardBoardType" 10
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiChassisVendor" "Apple Inc."
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiChassisType" 10
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiChassisVersion" "Mac-F22788AA"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiChassisSerial" "CSN12345678901234567"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiChassisAssetTag" "Apple"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiOEMVBoxVer" "Extended version info: 1.00.00"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/DmiOEMVBoxRev" "Extended revision info: 1A"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/ModelNumber" "Hitachi HTS543232A7A484"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/FirmwareRevision" "ES2OA60W"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/SerialNumber" "2E3024L1T2V9KA"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/piix3ide/0/Config/SecondaryMaster/ModelNumber" "Slimtype DVD A  DS8A8SH"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/piix3ide/0/Config/SecondaryMaster/FirmwareRevision" "KAA2"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/piix3ide/0/Config/SecondaryMaster/SerialNumber" "ABCDEF0123456789"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/piix3ide/0/Config/SecondaryMaster/ATAPIVendorId" "Slimtype"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/piix3ide/0/Config/SecondaryMaster/ATAPIProductId" "DVD A  DS8A8SH"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/piix3ide/0/Config/SecondaryMaster/ATAPIRevision" "KAA2"

%vboxman% setextradata "%VM%" "VBoxInternal/Devices/acpi/0/Config/AcpiOemId" "APPLE"
%vboxman% modifyvm "%VM%" --macaddress1 6CF0491A6E85
%vboxman% modifyvm "%VM%" --paravirtprovider legacy
%vboxman% modifyvm "%VM%" --hwvirtex on
%vboxman% modifyvm "%VM%" --vtxvpid on
%vboxman% modifyvm "%VM%" --vtxux on
%vboxman% modifyvm "%VM%" --apic on
%vboxman% modifyvm "%VM%" --pae on
%vboxman% modifyvm "%VM%" --longmode on
%vboxman% modifyvm "%VM%" --hpet on
%vboxman% modifyvm "%VM%" --nestedpaging on
%vboxman% modifyvm "%VM%" --largepages on

cd /d %vmscfgdir%

%vboxman% setextradata "%VM%" "VBoxInternal/Devices/acpi/0/Config/DsdtFilePath" "%vmscfgdir%ACPI-DSDT.bin"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/acpi/0/Config/SsdtFilePath" "%vmscfgdir%ACPI-SSDT.bin"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/vga/0/Config/BiosRom" "%vmscfgdir%vgabios386.bin"
%vboxman% setextradata "%VM%" "VBoxInternal/Devices/efi/0/Config/EfiRom" "%vmscfgdir%efi_amd64_fixed_6.1.6.fd"
@pause
