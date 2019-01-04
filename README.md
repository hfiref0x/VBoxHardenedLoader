
# VirtualBox Hardened Loader
## VirtualBox Hardened VM detection mitigation loader

For step by step guide further info see

https://github.com/hfiref0x/VBoxHardenedLoader/blob/master/Binary/install.md

If you compiled signed version of loader and driver 

https://github.com/hfiref0x/VBoxHardenedLoader/blob/master/Binary/install_signed.md

# System Requirements

x64 Windows 7/8/8.1/10;

VirtualBox 6.0.0 and later versions.

For version below VirtualBox 6.0 please use older release of this loader.

+ For versions 5.2.x use loader version 1.9.0 
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.9.0)

+ For versions 5.1.x use loader version 1.8.0 or 1.8.2
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.8.2)

+ For versions 5.0.0, 5.0.2, 5.0.8, 5.0.10, 5.0.12 use loader version 1.7.1
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.7.1)

Loader designed only for x64 Windows.

Administrative privilege is required.

# Warning
Binary files (ACPI tables, BIOS roms), batch scripts from loader version 1.9+ are NOT compatible with VirtualBox 5.1 and below.

# Oracle bug warning for VirtualBox 6.0.0
VirtualBox version 6.0.0 contain a bug that causes any EFI enabled guest to show black screen with any type of virtual display adapter other than VBoxVGA which is _not default_ setting (except the case when VM is created for old OS variants). If you want set the EFI option for guest, you should also go to Display settings and change video adapter type to VBoxVGA manually.

# Installation and use

For unsingned loader version (this is default version shipped on github) 
+ See README.txt in Binary directory for more info.

For singed loader version 
+ See README_SIGNED.txt in Binary directory for more info.


# Build 

Project comes with full source code.
In order to build from source you need:
1) Microsoft Visual Studio 2013 U4 and/or Visual Studio 2015/2017 for loader build.
2) Windows Driver Kit 8.1 U1 and later versions for driver build.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v120 for Visual Studio 2013;
  * v140 for Visual Studio 2015; 
  * v141 for Visual Studio 2017.
* For v140 and above set Target Platform Version (Project->Properties->General):
  * If v140 then select 8.1 (Note that Windows 8.1 SDK must be installed);
  * If v141 then select 10.0.17763.0 (Note that Windows 10.0.17763 SDK must be installed). 


# Project Contents

**Tsugumi - monitoring driver, x64** 

Purpose: patch VirtualBox dlls in runtime.

**Zekamashi - application, x64**

Purpose: set registry patch data for Tsugumi driver, notify monitoring driver about patch data change, stop monitoring. Controls driver behavior by sending Tsugumi requests from loader command line. Type loader /? in command line to view built-in help about supported commands and their syntax.

Since 1.8 version loader has integrated patch generator and it will attempt to generate patch table for currently installed VirtualBox version.

**Kasumi - application, x64**

Purpose: auxiliary utiliy to generate patch tables from VirtualBox VBoxDD dlls, generated table then can be used as input file to loader (Zekamashi).

> **Usage:** kasumi vboxdd_filename, for example: kasumi C:\Program Files\Oracle\VirtualBox\VBoxDD.dll

Not required for VBoxHardenedLoader work. Since 1.8 version integrated to Zekamashi loader and works automatically.


# Code Signing

See CodeSigning.txt in Source directory for more info.

# Linux support

https://github.com/hfiref0x/VBoxHardenedLoader/blob/master/Binary/linux.md

# Authors

(c) 2014 - 2019 VBoxHardenedLoader Project
