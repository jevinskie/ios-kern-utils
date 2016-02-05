# iOS Kernel Utilities

### Prerequisites

* Jailbroken Device
* `task_for_pid0` kernel patch (probably the case if jailbroken)

### Tools

kdump  - Tool to dump a running iOS kernel to a file
kmap   - Tool do visualize the kernel address space
kpatch - Tool to apply patches to a running kernel
kmem   - Tool to dump kernel memory to the console

### Build

    git clone https://github.com/Siguza/ios-kern-utils
    cd ios-kern-utils
    make

You may also specify the following environment variables:

Name | Function | Default Value
:-: | :-- | :--
IGCC | iOS compiler command | `xcrun -sdk iphoneos gcc`
IGCC_TARGET | target flags (can be arbitrary though) | `-arch arm64`
IGCC_FLAGS | installation flags (you probably don't wanna touch those) | `-F/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks -I/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/include -L/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/lib -L/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/lib/system`
SIGN | code signing utility | `codesign`

### TODO

* Find out why fat binaries won't work
* Linux support
* Make all the warnings go away
* Keep up with the original repo

Beware, chances are the device will panic and reboot.
