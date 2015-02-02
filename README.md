Foreign LINUX
======

Foreign LINUX is a dynamic binary translator and a Linux system call interface emulator for the Windows platform. It is capable of running *unmodified* Linux binaries on Windows without any drivers or modifications to the system. This provides another way of running Linux applications under Windows in constrast to Cygwin and other tools. See [Comparison](https://github.com/wishstudio/flinux/wiki/Comparison) for more details.

This project is in heavy development. It is currently capable of running many Linux utilities. Including but not limited to *bash*, *vim*, *python*, and *gcc*. I have also bootstrapped a working [ArchLinux](http://www.archlinux.org/) chroot environment with the package manager *pacman* working. Benefited by xterm-like terminal emulation, terminal based games like [vitetris](www.victornils.net/tetris/) and [nethack](http://www.nethack.org) are also playable. Socket handling is currently not feature complete, but is capable of running small HTTP utilities like *wget* and *curl*, and some basic X applications like *xeyes*, *xclock*, and *glxgears*, with the help of a native Windows X server like [Vcxsrv](sourceforge.net/projects/vcxsrv/).

Some major missing functions are file permissions, process management, signals, multi-threading, and more. Applications depending on these technologies will not work properly. Before trying Foreign Linux you should be warned that this is still in early stage, bad things like ***crashing your system*** or ***eating your harddisk*** may happen. Please back up your data in case. If you find any bugs, feel free to create an issue or contribute a patch.

Feature highlights
======
* Run unmodified Linux applications in a pure user-mode application, no privileged code or drivers or virtual machines
* Support both dynamically and statically compiled executables
* Support NTFS native hardlinks and emulated symbolic links
* Xterm-like terminal emulation on Win32 console
* Client-side networking (sockets) support

For a more technical perspective, see [this](https://github.com/wishstudio/flinux/wiki/Features).

User Guide
=====
To be documented until release. For developers, use [this guide]().

Comparison
=====
See [this](https://github.com/wishstudio/flinux/wiki/Comparison) for a comparison between other similar projects.

Development
======
See [this guide](https://github.com/wishstudio/flinux/wiki/Development) on how to compile this project.

License
======
GNU General Public License version 3 or above (GPLv3+)
