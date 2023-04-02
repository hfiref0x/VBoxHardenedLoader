
# VirtualBox Hardened Loader
## VirtualBox Hardened VM detection mitigation loader

## Note about archivation from 02 Apr 2023.
This project is no longer maintained since mid of 2020. Reasons are multiple:
1. Authors switched to another virtual environment and no longer need of use this bugged Oracle product.
2. For years of existence 2014-2020 a little of public contribution were made but a huge amount of PROFIT were made by these who used this loader for purposes this loader wasn't made (incluing ridiculous re-brands/game cheating etc). We are okay with it if you are contributing to source you are making profit from. None of them did this.

From now on switch to something else or fork and update this loader.
The features that need to be updated are:
1. Since Windows 11 "some update" Microsoft blocked Intel Nal driver which this loader is using to load it own driver (Tsugumi). **You will have to replace Intel Nal driver with something that works** (for example some provider from https://github/hfiref0x/kdu)
2. VBox ACPI tables, offsets and EFI VGA module patch weren't updated since mid 2020 - **you will have to fix it**.

# System Requirements

+ x64 Windows 7/8/8.1/10;
+ VirtualBox 6.1.6 and later versions;
+ Administrative privilege is required.

WARNING: This loader is incompatible with any VirtualBox below 6.1.2.

For version below VirtualBox 6.1.6 please use older release of this loader.

More about key changes in loader version 2 you can read here https://swapcontext.blogspot.com/2020/02/vboxhardenedloader-v2.html

+ For versions 6.0.x use loader version 1.10.0
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.10.0)

+ For versions 5.2.x use loader version 1.9.0 
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.9.0)

+ For versions 5.1.x use loader version 1.8.0 or 1.8.2
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.8.2)

+ For versions 5.0.0, 5.0.2, 5.0.8, 5.0.10, 5.0.12 use loader version 1.7.1
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.7.1)


# Installation and use guide

https://github.com/hfiref0x/VBoxHardenedLoader/blob/master/Binary/howto.md


# Build 

Project comes with full source code.
In order to build from source you need:
1) Microsoft Visual Studio 2019 for loader build.
2) Windows Driver Kit 8.1/10 and later versions for driver build.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v120 for Visual Studio 2013;
  * v140 for Visual Studio 2015; 
  * v141 for Visual Studio 2017;
  * v142 for Visual Studio 2019.
* For v140 and above set Target Platform Version (Project->Properties->General):
  * If v140 then select 8.1;
  * If v141/v142 then select 10. 


# Project Contents

**Tsugumi - monitoring driver, x64** 

Purpose: patch VirtualBox dlls in runtime.

**Zekamashi - application, x64**

Purpose: load Tsugumi monitoring driver, stop monitoring. Type loader /? in command line to view built-in help about supported commands and their syntax.


# Linux support

https://github.com/hfiref0x/VBoxHardenedLoader/blob/master/Binary/linux.md


# Support and donations

VBoxHardenedLoader is Free Software and is made available free of charge.
Your donation, which is purely optional, supports project development and maintaining.
If you like the software, you can consider donation which you can do anonymously using the following BTC address

* 3DU68VrwZYHVSYXenQMG123utkYrFGms3b

# Authors

(c) 2014 - 2020 VBoxHardenedLoader Project
