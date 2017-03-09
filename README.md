# machkextdump
Dump Kext information from Macos. Support batch analysis. The disassembly framework used is [Capstone](http://www.capstone-engine.org/)

[![Contact](https://img.shields.io/badge/contact-@cocoahuke-fbb52b.svg?style=flat)](https://twitter.com/cocoahuke) [![build](https://travis-ci.org/cocoahuke/ioskextdump_32.svg?branch=master)](https://github.com/cocoahuke/machkextdump) [![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cocoahuke/ioskextdump_32/blob/master/LICENSE) [![paypal](https://img.shields.io/badge/Donate-PayPal-039ce0.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=EQDXSYW8Z23UY)

###For iOS:
**32bit: [ioskextdump_32](https://github.com/cocoahuke/ioskextdump_32)**
**64bit: [ioskextdump](https://github.com/cocoahuke/ioskextdump)**

# How to use

**Download**
```bash
git clone https://github.com/cocoahuke/machkextdump.git && cd machkextdump
```
**Compile and install** to /usr/local/bin/

```bash
make
make install
```
**Usage**
```
Usage: mackextdump [-s <specify a single exxc file of kext to analysis>] <Extensions folder>
```
`-s` example:
```
mackextdump -s /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily
```
or batch analysis kexts copy that from `/System/Library/Extensions`
```
mackextdump /System/Library/Extensions
```
**Save the batch analysis output as file**, so you got a file that include all kext class, methods name and vtable address, do some searching in this file may give some help to you

mostly rdx are 0xffffffffffffffff, because its super class didn't defined in a same binary file, it reference from outside

All addresses from output are file offset, not virtual memory address

Tested on Macos 10.12.1

**Example to use**

```
******** 43:com.apple.AMDRadeonAccelerator *******
**/Users/huke/Desktop/mackext_copy/10_12_1_kext/AMDRadeonX3000.kext/Contents/MacOS/AMDRadeonX3000**

(0x3c6d8)->OSMetaClass:OSMetaClass call 4 args list
rdi:0x567488
rsi:AMDR8xxGLContext
rdx:0xffffffffffffffff
rcx:0x1d58
vtable_start: 0x236b00

vtable functions:
AMDR8xxGLContext_E
AMDR8xxGLContext_
AMDR8xxGLContext_getMetaClass
AMDR8xxGLContext_getTargetAndMethodForIndex
IOAccelContext2_getOwningTask
IOAccelContext2_getGPUTask
IOAccelContext2_getOwningTaskPid
```
