rem @echo off

rem BIOS/AHCI mode

rem vboxman is the full path to the vboxmanage executable
rem vmscfgdir is the path to directory that keeps vbox custom configuration data (bioses, tables etc)

set vboxman="C:\Program Files\Oracle\VirtualBox\vboxmanage.exe"
set vmscfgdir=D:\Virtual\VBOX\Settings\

%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor" "Asus"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion" "MB52.88Z.0088.B05.0904162222"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate" "08/10/13"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor" "5"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor" "9"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMajor" "1"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMinor" "0"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "Asus"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "MyBook5,2"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion" "1.0"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial" "CSN12345678901234567"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU" "FM550EA#ACB"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily" "Ultrabook"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid" "B5FA3000-9403-81E0-3ADA-F46D045CB676"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor" "Asus"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct" "Mac-F22788AA"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion" "3.0"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardSerial" "BSN12345678901234567"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardAssetTag" "Base Board Asset Tag#"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardLocInChass" "Board Loc In"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiBoardBoardType" 10
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor" "Asus Inc."
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisType" 10
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisVersion" "Mac-F22788AA"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisSerial" "CSN12345678901234567"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiChassisAssetTag" "WhiteHouse"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer" "Extended version info: 1.00.00"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev" "Extended revision info: 1A"
%vboxman% setextradata "%1" "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "Hitachi HTS543230AAA384"
%vboxman% setextradata "%1" "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "ES2OA60W"
%vboxman% setextradata "%1" "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "2E3024L1T2V9KA"
%vboxman% setextradata "%1" "VBoxInternal/Devices/ahci/0/Config/Port1/ModelNumber" "Slimtype DVD A  DS8A8SH"
%vboxman% setextradata "%1" "VBoxInternal/Devices/ahci/0/Config/Port1/FirmwareRevision" "KAA2"
%vboxman% setextradata "%1" "VBoxInternal/Devices/ahci/0/Config/Port1/SerialNumber" "ABCDEF0123456789"
%vboxman% setextradata "%1" "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIVendorId" "Slimtype"
%vboxman% setextradata "%1" "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIProductId" "DVD A  DS8A8SH"
%vboxman% setextradata "%1" "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIRevision" "KAA2"


%vboxman% setextradata "%1" "VBoxInternal/Devices/acpi/0/Config/AcpiOemId" "ASUS"
%vboxman% modifyvm "%1" --macaddress1 6CF0491A6E12
%vboxman% modifyvm "%1" --paravirtprovider legacy

cd /d %vmscfgdir%

%vboxman% setextradata "%1" "VBoxInternal/Devices/acpi/0/Config/DsdtFilePath" "%vmscfgdir%ACPI-DSDT.bin"
%vboxman% setextradata "%1" "VBoxInternal/Devices/acpi/0/Config/SsdtFilePath" "%vmscfgdir%ACPI-SSDT1.bin"
%vboxman% setextradata "%1" "VBoxInternal/Devices/vga/0/Config/BiosRom" "%vmscfgdir%videorom.bin"
%vboxman% setextradata "%1" "VBoxInternal/Devices/pcbios/0/Config/BiosRom" "%vmscfgdir%pcbios.bin"
%vboxman% setextradata "%1"  "VBoxInternal/Devices/pcbios/0/Config/LanBootRom" "%vmscfgdir%pxerom.bin"
%vboxman% modifyvm "%1" --bioslogoimagepath  "%vmscfgdir%splash.bmp"

@pause
