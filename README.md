# iOS Kernel Utilities

### Download

Just want the binaries?  
Head over to [Releases](https://github.com/Siguza/ios-kern-utils/releases). :)

### Prerequisites

* Jailbroken Device
* `task_for_pid0` kernel patch (probably the case if jailbroken on iOS < 9)
* If you don't have XCode:
  * GNU make
  * C compiler for iOS
  * Code signing utility

### Tools

Name | Function
:-: | :--
kdump | Dump a running iOS kernel to a file
kmap | Visualize the kernel address space
kpatch | Apply patches to a running kernel
kmem | Dump kernel memory to the console

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
