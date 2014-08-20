Foreign Linux
======

Foreign Linux is a Linux system call translator for the Windows platform. It can run *unmodified* Linux binaries on Windows without any drivers or modifications to the system. You can think it as [WINE](http://www.winehq.org) but in reverse. 

This project is still in heavy development. It's still buggy and not meant for everyday use.

Feature highlights
======

* Copy-on-Write fork(2) implementation
* NTFS native hardlink
* Cygwin-style emulated symlink
* Interprocess pipes
* vt102 terminal emulation on Win32 console

Comparison
======
Here is a quick comparison between previous similar projects. All these projects are dead now and some still doesn't work for Win8 x64 and that's the main reason I started Foreign Linux.

* [Cooperative Linux](http://colinux.org): Cooperative Linux is a patchset for the Linux kernel. It allows the kernel to run in VMX mode alongside Windows. Thus it is more like a lightweight virtual machine but with minimal overhead. The biggest issue of coLinux is the need to use a kernel mode driver. It works fine for x86. But the driver hasn't been ported to x64 for many years.

* [atratus](http://atratus.org): atratus uses a server-client architecture. The "kernel" process manages all "client" data and acts as a debugger of the client processes. The benefit of this approach is that clients can get a very clean memory layout which is useful for fork(2), and the file sharing semantics can be easy to implement. But the downsides are the need to do process scheduling manually, and true multithreading will hardly work as one debug event will pause the whole process.

* [LBW](http://lbw.sourceforge.net): Linux Binaries on Windows uses Interix to implmenet many POSIX functions, notably fork(2). As Interix is now deprecated, LBW is no longer useful.

* [Line](http://sourceforge.net/projects/line): Linux Is Not an Emulator is a very early project to run linux binaries on Windows. It sill work on Win8 x64 as I tested. It uses Cygwin for POSIX layer thus no efficient fork(2).
