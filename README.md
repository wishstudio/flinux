Foreign LINUX
======

[![Join the chat at https://gitter.im/wishstudio/flinux](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/wishstudio/flinux?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![Build status](https://ci.appveyor.com/api/projects/status/a340ver0l85l14tf?svg=true)](https://ci.appveyor.com/project/wishstudio/flinux)

Foreign LINUX is a dynamic binary translator and a Linux system call interface emulator for the Windows platform. It is capable of running *unmodified* Linux binaries on Windows without any drivers or modifications to the system. This provides another way of running Linux applications under Windows in constrast to Cygwin and other tools. There is a  [comparison](https://github.com/wishstudio/flinux/wiki/Comparison) over existing projects.

This project is in heavy development. It is currently capable of running many Linux utilities. Including but not limiting to:

* Shells: **bash**, **zsh**
* Editors: **vim**, **nano**
* Programming environments: **python**, **gcc**
* Package managers: **pacman**
* Terminal-based games: **vitetris**, **nethack**
* Network utilities: **wget**, **curl**, **ssh**
* X applications: **xeyes**, **xclock**, **glxgears**

Some major missing functions are file permissions, process management, multi-threading, and more. Applications depending on these technologies will not work properly.

How to use
=====
Foreign LINUX is still in early stage, bad things like *crashing your system* or *eating your harddisk* may happen. **You have been warned.**

For users who just want to give it a try. Download a premade Arch Linux environment [here](https://xysun.me/static/flinux-archlinux.7z). Then visit [Beginner's Guide](https://github.com/wishstudio/flinux/wiki/Beginner's-Guide).

For just the binary executables, visit [release page](https://github.com/wishstudio/flinux/releases). For getting the latest development snapshot, visit [here](https://ci.appveyor.com/project/wishstudio/flinux/build/artifacts).

For developers, you can also visit [this guide](https://github.com/wishstudio/flinux/wiki/ArchLinux-installation-steps) for detailed bootstrapping steps of an ArchLinux chroot.

Screenshots
=====
![Screenshot](https://xysun.me/static/flinux-screenshot.png)

Development
======
See [development](https://github.com/wishstudio/flinux/wiki/Development).

Contact
======
Mailing list: flinux@googlegroups.com ([subscribe](https://groups.google.com/forum/#!forum/flinux))

Freenode IRC: #flinux

License
======
Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>

The source code is licensed under GNU General Public License version 3 or above (GPLv3+)
