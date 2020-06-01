#! /bin/sh

vboxmanage setextradata "$1" "VBoxInternal/CPUM/EnableHVP" 0

vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBIOSVendor" "LENOVO"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBIOSVersion" "N1MET31W (1.16 )"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBIOSReleaseDate" "03/10/2017"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBIOSReleaseMajor" "3"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBIOSReleaseMinor" "91"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBIOSFirmwareMajor" "3"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBIOSFirmwareMinor" "91"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiSystemVendor" "LENOVO"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiSystemProduct" "20HQZ2YHUS"

vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiSystemVersion" "ThinkPad X1 Carbon 5th"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiSystemSerial" "PF0N9BA2"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiSystemSKU" "To Be Filled By O.E.M."
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiSystemFamily" "To Be Filled By O.E.M."
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiSystemUuid" "4C3C615B-D626-B211-A85C-C9A2E7368262"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBoardVendor" "LENOVO"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBoardProduct" "20HQZ2YHUS"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBoardVersion" "SDK0J40697 WIN"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBoardSerial" "L1HF6BG000Y"

vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBoardAssetTag" "0123456789ABCDEF"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBoardLocInChass" "To Be Filled By O.E.M."
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiBoardBoardType" 10
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiChassisVendor" "LENOVO"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiChassisType" 6
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiChassisVersion" "To Be Filled By O.E.M."
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiChassisSerial" "PF0N9BA2"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiChassisAssetTag" "0123456789ABCDEF"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiOEMVBoxVer" "Extended version info: 3.00.00"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/DmiOEMVBoxRev" "Extended revision info: 1E"

vboxmanage setextradata "$1" "VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber" "THNSF5256GPUK TOSHIBA"
vboxmanage setextradata "$1" "VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision" "51025KLA"
vboxmanage setextradata "$1" "VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber" "96IS10F4T4UT"
vboxmanage setextradata "$1" "VBoxInternal/Devices/ahci/0/Config/Port1/ModelNumber" "HL-DT-ST DVDRAM GUE2P"
vboxmanage setextradata "$1" "VBoxInternal/Devices/ahci/0/Config/Port1/FirmwareRevision" "AS01"
vboxmanage setextradata "$1" "VBoxInternal/Devices/ahci/0/Config/Port1/SerialNumber" "KRFG74G5310"
vboxmanage setextradata "$1" "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIVendorId" "Slimtype"
vboxmanage setextradata "$1" "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIProductId" "DVDRAM GUE2P"
vboxmanage setextradata "$1" "VBoxInternal/Devices/ahci/0/Config/Port1/ATAPIRevision" "AS01"

vboxmanage setextradata "$1" "VBoxInternal/Devices/acpi/0/Config/AcpiOemId" "LENOVO"
vboxmanage setextradata "$1" "VBoxInternal/Devices/efi/0/Config/EfiRom" "/home/user/vm/VBoxEFI64.fd"

vboxmanage modifyvm "$1" --paravirtprovider legacy
vboxmanage modifyvm "$1" --chipset ich9
vboxmanage modifyvm "$1" --macaddress1 2C49443BC482
vboxmanage modifyvm "$1" --hwvirtex on
vboxmanage modifyvm "$1" --vtxvpid on
vboxmanage modifyvm "$1" --vtxux on
vboxmanage modifyvm "$1" --apic on
vboxmanage modifyvm "$1" --pae on
vboxmanage modifyvm "$1" --longmode on
vboxmanage modifyvm "$1" --hpet on
vboxmanage modifyvm "$1" --nestedpaging on
vboxmanage modifyvm "$1" --largepages on
