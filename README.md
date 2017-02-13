# iOS Kernel Utilities

Beware, chances are the device will panic and reboot.

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

A kernel patch is required for these tools to work, since access to kernel memory is natively unavailable for obvious reasons.  
That patch is normally referred to as `task-for-pid-zero` (short `tfp0`), and is included in almost every public jailbreak.

The latest release of these tools is confirmed to work with:

* p0sixspwn on 6.1.x
* TaiG on 8.4
* Pangu9 on 9.1
* [qwertyoruiop's jailbreakme](https://jbme.qwertyoruiop.com/) on 9.3.x
* Yalu102 (beta4 or later) on 10.0.1-10.2

Jailbreaks that **DO NOT** seem to enable `tfp0`, and thus **DO NOT** work with kern-utils:

* Pangu9 on 9.0.x (but can be enabled with [cl0ver](https://github.com/Siguza/cl0ver))
* Pangu9 on 9.2-9.3.3 (but see qwertyoruiop's jailbreakme)

If you have information about how the kernel task port can be obtained in these versions, please [open a ticket](https://github.com/Siguza/ios-kern-utils/issues/new) and tell me.

### Tools

Name      | Function
:-------: | :------------------------------------------------
`kdump`   | Dump a running iOS kernel to a file
`kmap`    | Visualize the kernel address space
`kpatch`  | Apply patches to a running kernel
`kmem`    | Dump kernel memory to the console
`khead`   | Parse and display the Mach-O header of the kernel
`nvpatch` | Allow all NVRAM variables to be changed

### Building

    git clone https://github.com/Siguza/ios-kern-utils
    cd ios-kern-utils
    make        # build just the binaries
    make deb    # build a deb file for Cydia
    make xz     # package binaries to a .tar.xz
    make dist   # deb && xz

For `make` you may also specify the following environment variables:

<table>
    <tr>
        <th align="center" rowspan="2">Name</th>
        <th align="center" rowspan="2">Function</th>
        <th align="center" colspan="3">Default value</th>
    </tr>
    <tr>
        <th align="center">OS X</th>
        <th align="center">iOS</th>
        <th align="center">Linux</th>
    </tr>
    <tr>
        <td align="center"><code>IGCC</code></td>
        <td align="center">iOS compiler</td>
        <td align="center"><code>xcrun -sdk iphoneos gcc</code></td>
        <td align="center"><code>clang</code></td>
        <td align="center"><code>ios-clang</code></td>
    </tr>
    <tr>
        <td align="center"><code>IGCC_ARCH</code></td>
        <td align="center">Target architecture(s)</td>
        <td align="center" colspan="3"><code>-arch armv7 -arch arm64</code></td>
    </tr>
    <tr>
        <td align="center"><code>IGCC_FLAGS</code></td>
        <td align="center">Custom compiler flags</td>
        <td align="center" colspan="3"><i>none</i></td>
    </tr>
    <tr>
        <td align="center"><code>STRIP</code></td>
        <td align="center">Symbol remover utility</td>
        <td align="center"><code>xcrun -sdk iphoneos strip</code></td>
        <td align="center"><code>strip</code></td>
        <td align="center"><code>ios-strip</code></td>
    </tr>
    <tr>
        <td align="center"><code>SIGN</code></td>
        <td align="center">Code signing utility</td>
        <td align="center"><code>codesign</code></td>
        <td align="center" colspan="2"><code>ldid</code></td>
    </tr>
    <tr>
        <td align="center"><code>SIGN_FLAGS</code></td>
        <td align="center">Code signing flags</td>
        <td align="center"><code>-s - --entitlements misc/ent.xml</code></td>
        <td align="center" colspan="2"><code>-Smisc/ent.xml</code></td>
    </tr>
</table>

### License

[MIT](https://github.com/Siguza/cl0ver/blob/master/LICENSE).

[Original project](https://github.com/saelo/ios-kern-utils) by [Samuel Groß](https://github.com/saelo).  
`nvpatch` is largely based on [`nvram_patcher`](https://github.com/realnp/nvram_patcher) by [Pupyshev Nikita](https://github.com/realnp).  
Maintained and updated for iOS 8 and later by [Siguza](https://github.com/Siguza).  

### TODO

* Test on Linux
* Keep up with the original repo
