# iOS Kernel Utilities

### Download

Just want the binaries?  
Head over to [Releases](https://github.com/Siguza/ios-kern-utils/releases). :)

### Prerequisites

* Jailbroken Device
* `tfp0` kernel patch (see below)
* If you don't have XCode:
  * GNU make
  * C compiler for iOS
  * Code signing utility

### `tfp0` compatibility

A kernel patch is required for these tools to work, since the API for getting the kernel task is natively disabled for obvious reasons.  
That patch is normally referred to as `tfp0` or `task_for_pid0`, and is included (in some form) in almost every public jailbreak.

The latest release is confirmed to work with:

* p0sixspwn on 6.1.6
* TaiG on 8.4
* Pangu9 on 9.1

It is confirmed to **NOT** work with:

* Pangu9 on 9.0.x

### Tools

Name | Function
:-: | :--
kdump | Dump a running iOS kernel to a file
kmap | Visualize the kernel address space
kpatch | Apply patches to a running kernel
kmem | Dump kernel memory to the console
khead | Parse and display the Mach-O header of the kernel

### Build

    git clone https://github.com/Siguza/ios-kern-utils
    cd ios-kern-utils
    make

You may also specify the following environment variables:

Name | Function | Default value
:-: | :-- | :--
`IGCC` | iOS compiler command | **OS X**: `xcrun -sdk iphoneos gcc`<br>**Linux**: `ios-clang`<br>**iOS**: `clang`
`IGCC_TARGET` | target flags | `-arch armv7 -arch arm64`
`IGCC_FLAGS` | compiler flags | *none*
`SIGN` | code signing utility | **OS X**: `codesign`<br>**Linux**: `ldid`<br>**iOS**: `ldid`
`SIGN_FLAGS` | code signing flags | if `SIGN == codesign`: `-s - --entitlements misc/ent.xml`<br>if `SIGN == ldid`: `-Smisc/ent.xml`<br>otherwise: *none*

### TODO

* Test on Linux
* Keep up with the original repo

Beware, chances are the device will panic and reboot.
