Foreign LINUX
======

[![Join the chat at https://gitter.im/wishstudio/flinux](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/wishstudio/flinux?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![Build status](https://ci.appveyor.com/api/projects/status/a340ver0l85l14tf?svg=true)](https://ci.appveyor.com/project/wishstudio/flinux)

Foreign LINUX is a dynamic binary translator and a Linux system call interface emulator for the Windows platform. It is capable of running *unmodified* Linux binaries on Windows without any drivers or modifications to the system. This provides another way of running Linux applications under Windows in constrast to Cygwin and other tools. It now runs a large bunch of console applications and some GUI applications.

Quick start
=====
Download a premade archlinux environment [here](https://xysun.me/static/flinux-archlinux.7z).

Extract it anywhere on your harddrive. Then run `run_bash.cmd` to open bash. You will get a minimal archlinux environment.

Then you can run `pacman -Syu` to update all packages to the current version. Then use `pacman -S <name>` to install any packages you want.

Development snapshots: you can download development versions of the software [here](https://ci.appveyor.com/project/wishstudio/flinux/build/artifacts). Just replace the two executables (flinux.exe and flog.exe) for an update.

[Documentation](https://github.com/wishstudio/flinux/wiki)

Contributing
=====
This project still lacks functionality required for many Linux applications. Any help is greatly appreciated. You can contribute using the following ways:

* Contribute code. Visit [development guideline](https://github.com/wishstudio/flinux/wiki/Development-Guideline) and our [TODO list](https://github.com/wishstudio/flinux/wiki/TODO-List).
* Test programs and report bugs. Read [report a bug](https://github.com/wishstudio/flinux/wiki/Report-a-bug) first.
* Help with the documentations.

License
=====
This software is licensed in GPLv3+.
