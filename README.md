
#VirtualBox Hardened Loader
## VirtualBox Hardened VM detection mitigation loader

For step by step guide further info see
https://github.com/hfiref0x/VBoxHardenedLoader/blob/master/Binary/install.md

# System Requirements

x64 Windows 7/8/8.1/10;

VirtualBox 5.1 and later versions.

For version below VirtualBox 5.0 use older release of this loader.
For versions 5.0.0, 5.0.2, 5.0.8, 5.0.10, 5.0.12 please use loader version 1.5.

Loader designed only for x64 Windows.

Administrative privilege is required.


# Installation and use

For unsingned loader version (this is default version shipped on github) 
+ See README.txt in Binary directory for more info.

For singed loader version 
+ See README_SIGNED.txt in Binary directory for more info.


# Build 

Project comes with full source code.
In order to build from source you need:
Microsoft Visual Studio 2013 U4 and/or Visual Studio 2015 U2 and later versions for loader build.
Windows Driver Kit 8.1 U1 and later versions for driver build.


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


# Authors

(c) 2014 - 2017 VBoxHardenedLoader Project
