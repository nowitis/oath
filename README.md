> ⚠️ this app is WiP and nonfunctional! ⚠️

# TK1 OATH/OTP app

This repository will contain an application to run on the TKey 
USB security stick ("device app"), as well as companion client app 
("client app") running on the host computer. The client app loads
a OTP archive, encrypted using device secrets (thus tying the OTP 
codes to the key, as is the security model for 2FA) to the key, 
which will generate the OTP codes. 

## Building
We recommend building the device app using Podman, and the client app
using host tools, in this order. 

### Building the device app

You have two options, either Tillitis' OCI image
`ghcr.io/tillitis/tkey-builder` for use with a rootless podman setup,
or native tools.

In either case you need the device libraries in a directory next to
this one. The device libraries are available in:

https://github.com/tillitis/tkey-libs

Clone them next this repo and build them first.

#### Building the device app with Podman

Tillis provides an OCI image with all tools you can use to build the
tkey-libs and the apps. If you have `make` and Podman installed you
can us it like this in the `tkey-libs` directory and then this
directory:

```
make podman-deviceapp
```

and the key app should be built. This assumes a working rootless
podman. On Ubuntu 22.10, running

```
apt install podman rootlesskit slirp4netns
```

should be enough to get you a working Podman setup.

#### Building the device app with host tools

To build with native tools you need the `clang`, `llvm`, `lld`,
`golang` packages installed. Version 15 or later of LLVM/Clang is
required (with riscv32 support and Zmmul extension). Ubuntu 22.10
(Kinetic) is known to have this and work. Please see
[toolchain_setup.md](https://github.com/tillitis/tillitis-key1/blob/main/doc/toolchain_setup.md)
(in the tillitis-key1 repository) for detailed information on the
currently supported build and development environment.

Clone and build the device libraries first:

```
$ git clone https://github.com/tillitis/tkey-libs
$ cd tkey-libs
$ make
```

Then go back to this directory and build everything:

```
$ make deviceapp
```

If you cloned `tkey-libs` to somewhere else then the default set
`LIBDIR` to the path of the directory.

If your available `objcopy` is anything other than the default
`llvm-objcopy`, then define `OBJCOPY` to whatever they're called on
your system.

The device apps can be run both on the hardware TKey, and on a QEMU
machine that emulates the platform. In both cases, the client apps
(the program that runs on your computer, for example `tkey-ssh-agent`)
will talk to the app over a serial port, virtual or real. There is a
separate section below which explains running in QEMU.

### Building the client app
We advise to build the client app for your machine using host tools: 
see the above section for host tools requirements.

To build the client app:

```
$ make client
```

## Running device apps

Plug the USB stick into your computer. If the LED in one of the outer
corners of the USB stick is a steady white, then it has been
programmed with the standard FPGA bitstream (including the firmware).
If it is not then please refer to
[quickstart.md](https://github.com/tillitis/tillitis-key1/blob/main/doc/quickstart.md)
(in the tillitis-key1 repository) for instructions on initial
programming of the USB stick.

Before running, here are some considerations regarding the connection
between client app and device app. 

#### Users on Linux

Running `lsusb` should list the USB stick as `1207:8887 Tillitis
MTA1-USB-V1`. On Linux, the TKey's serial port device path is
typically `/dev/ttyACM0` (but it may end with another digit, if you
have other devices plugged in). The client apps tries to auto-detect
serial ports of TKey USB sticks, but if more than one is found you'll
need to choose one using the `--port` flag.

However, you should make sure that you can read and write to the
serial port as your regular user.

One way to accomplish this is by installing the provided
`system/60-tkey.rules` in `/etc/udev/rules.d/` and running `udevadm
control --reload`. Now when a TKey is plugged in, its device path
(like `/dev/ttyACM0`) should be read/writable by you who are logged in
locally (see `loginctl`).

Another way is becoming a member of the group that owns the serial
port. On Ubuntu that group is `dialout`, and you can do it like this:

```
$ id -un
exampleuser
$ ls -l /dev/ttyACM0
crw-rw---- 1 root dialout 166, 0 Sep 16 08:20 /dev/ttyACM0
$ sudo usermod -a -G dialout exampleuser
```

For the change to take effect everywhere you need to logout from your
system, and then log back in again. Then logout from your system and
log back in again. You can also (following the above example) run
`newgrp dialout` in the terminal that you're working in.

Your TKey is now running the firmware. Its LED is a steady white,
indicating that it is ready to receive an app to run.

#### User on MacOS

The client apps tries to auto-detect serial ports of TKey USB sticks,
but if more than one is found you'll need to choose one using the
`--port` flag.

To find the serial ports device path manually you can do `ls -l
/dev/cu.*`. There should be a device named like `/dev/cu.usbmodemN`
(where N is a number, for example 101). This is the device path that
might need to be passed as `--port` when running the client app.

You can verify that the OS has found and enumerated the USB stick by
running:

```
ioreg -p IOUSB -w0 -l
```

There should be an entry with `"USB Vendor Name" = "Tillitis"`.


### Usage
Run the app by invoking:

```
$ runpattern --pattern ".../---/..."
```

This will blink the TKey LED according to the SOS Morse pattern. The 
app will also perform a validation of the pattern loaded on the TKey, 
demonstrating bidirectional communication between client and device 
app.


## System

For more details, please see [Tillitis documentation](https://github.com/tillitis/tillitis-key1/blob/main/doc/system_description/software.md)


## Licenses and SPDX tags

Unless otherwise noted, the project sources are licensed under the
terms and conditions of the "GNU General Public License v2.0 only":

> Copyright Tillitis AB.
>
> These programs are free software: you can redistribute it and/or
> modify it under the terms of the GNU General Public License as
> published by the Free Software Foundation, version 2 only.
>
> These programs are distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
> General Public License for more details.

> You should have received a copy of the GNU General Public License
> along with this program. If not, see:
>
> https://www.gnu.org/licenses

See [LICENSE](LICENSE) for the full GPLv2-only license text.

External source code we have imported are isolated in their own
directories. They may be released under other licenses. This is noted
with a similar `LICENSE` file in every directory containing imported
sources.

The project uses single-line references to Unique License Identifiers
as defined by the Linux Foundation's [SPDX project](https://spdx.org/)
on its own source files, but not necessarily imported files. The line
in each individual source file identifies the license applicable to
that file.

The current set of valid, predefined SPDX identifiers can be found on
the SPDX License List at:

https://spdx.org/licenses/

All contributors must adhere to the [Developer Certificate of Origin](dco.md).
