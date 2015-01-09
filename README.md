Foreign LINUX
======

Foreign LINUX is a Linux system call translator for the Windows platform. It is capable of running *unmodified* Linux binaries on Windows without any drivers or modifications to the system.

This project is still in heavy development. It's still buggy and not meant for everyday use. On the other hand it already runs a lot of Linux utilities, including *bash*, *coreutils*, *nano*, *python*, *wget*, etc.

Feature highlights
======

* Pure user-mode application, no privileged code or drivers
* Copy-on-Write fork() implementattion
* On-demand paging to save memory and improve fork performance
* Dynamically and statically compiled executables
* NTFS native hardlink
* Emulated symlink
* Interprocess pipes
* vt100 terminal emulation on Win32 console
* Sockets

Implemenation details
======
Foreign LINUX serves as a low level emulator (LLE) unlike WINE or cygwin which is an HLE (high leval emulator). We only implement kernel system calls and use the original unmodified system librareis to provide common ABIs. This greatly reduces the amount of work and improves emulation accuracy.


Foreign LINUX dynamically translates Linux system calls to their Windows equivalents, or emulates them if not directly available natively (notably fork). This is like [WINE](http://www.winehq.org). But due to some incompatiblities between the two systems and the limitations of Windows, the binary cannot be directly run like in WINE. Instead I implemented a dynamic binary translator to process the binaries and transform the incompatible bits before it is run.

Comparison
======
Here is a quick comparison between previous similar projects. All these projects are dead now and some still doesn't work for Win8 x64 and that's the main reason I started Foreign Linux.

* [Cooperative Linux](http://colinux.org): Cooperative Linux is a patchset for the Linux kernel. It allows the kernel to run in VMX mode alongside Windows. Thus it is more like a lightweight virtual machine but with minimal overhead. The biggest issue of coLinux is the need to use a kernel mode driver. It works fine for x86. But the driver hasn't been ported to x64 for many years.

* [atratus](http://atratus.org): atratus uses a server-client architecture. The "kernel" process manages all "client" data and acts as a debugger of the client processes. The benefit of this approach is that clients can get a very clean memory layout which is useful for fork(), and the file sharing semantics can be easy to implement. But the downsides are the need to do process scheduling manually, and true multithreading will hardly work as one debug event will pause the whole process.

* [LBW](http://lbw.sourceforge.net): Linux Binaries on Windows uses Interix to implmenet many POSIX functions, notably fork(). As Interix is now deprecated, LBW is no longer useful.

* [Line](http://sourceforge.net/projects/line): Linux Is Not an Emulator is a very early project to run linux binaries on Windows. It sill work on Win8 x64 as I tested. It uses Cygwin for POSIX layer thus no efficient fork().

Development
======
You need dlltool.exe from mingw for generating the import library for ntdll.dll. Add it to your PATH and you should be able to compile the Visual Studio project.
