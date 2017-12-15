# CTF Challenge 示例

angr 在 CTF 中经常被使用，这些都是使用这个例子的脚本，大部分来自 Shellphish，也有很多其他队伍的

## ReverseMe example: HackCon 2016 - angry-reverser

脚本作者： Stanislas Lejay (github: [@P1kachu](https://github.com/P1kachu))

脚本运行时间：约 31 分钟

[二进制程序](https://github.com/angr/angr-doc/tree/master/examples/hackcon2016_angry-reverser/yolomolo) 与 [脚本](https://github.com/angr/angr-doc/tree/master/examples/hackcon2016_angry-reverser/solve.py)

## ReverseMe example: SecurityFest 2016 - fairlight

脚本作者： chuckleberryfinn (github: [@chuckleberryfinn](https://github.com/chuckleberryfinn))

脚本运行时间：约 20 秒

一道简单的逆向题，对一个命令行参数进行十四次检查。
使用 angr 不用进行逆向就可以轻松解决这个问题。

[二进制程序](https://github.com/angr/angr-doc/tree/master/examples/securityfest_fairlight/fairlight) 与 [脚本](https://github.com/angr/angr-doc/tree/master/examples/securityfest_fairlight/solve.py)

## ReverseMe example: DEFCON Quals 2016 - baby-re

- Script 0

    作者： David Manouchehri (github: [@Manouchehri](https://github.com/Manouchehri))

    脚本运行时间： 8 分钟

- Script 1

    作者： Stanislas Lejay (github: [@P1kachu](https://github.com/P1kachu))

    脚本运行时间： 11 秒

[二进制程序](https://github.com/angr/angr-doc/blob/master/examples/defcon2016quals_baby-re_1/baby-re) 与脚本：
* [script0](https://github.com/angr/angr-doc/tree/master/examples/defcon2016quals_baby-re_0/solve.py)
* [script1](https://github.com/angr/angr-doc/tree/master/examples/defcon2016quals_baby-re_1/solve.py)

## ReverseMe example: Google CTF - Unbreakable Enterprise Product Activation (150 points)

Script 0 作者： David Manouchehri (github: [@Manouchehri](https://github.com/Manouchehri))

脚本运行时间： 4.5 秒

Script 1 作者： Adam Van Prooyen (github: [@docileninja](https://github.com/docileninja))

脚本运行时间： 6.7 秒

对一个 Linux 二进制程序的命令行参数进行一系列的约束检查

Challenge 描述：
> 帮助我们激活这个产品 - 我们失去了我们的许可证密钥 :(
>
> 你是我们唯一的希望！

[script 0](https://github.com/angr/angr-doc/tree/master/examples/google2016_unbreakable_0) 和 [script_1](https://github.com/angr/angr-doc/tree/master/examples/google2016_unbreakable_1)

## ReverseMe example: EKOPARTY CTF - Fuckzing reverse (250 points)

作者： Adam Van Prooyen (github: [@docileninja](https://github.com/docileninja))

脚本运行时间： 29 秒

以队伍名字作为 Linux 二进制程序的输入并进行一系列的约束检查

Challenge 描述：
> 需要满足几百个约束，你能完成吗？

[二进制程序与脚本](https://github.com/angr/angr-doc/tree/master/examples/ekopartyctf2016_rev250) 更多信息可以参阅作者的 [write-up](http://van.prooyen.com/reversing/2016/10/30/Fuckzing-reverse-Writeup.html)

## ReverseMe example: WhiteHat Grant Prix Global Challenge 2015 - Re400

作者： Fish Wang (github: @ltfish)

脚本运行时间： 5.5 秒

接受一个 flag 作为参数的 Windows 程序，反馈告诉你 flag 是否正确

必须手动修正一些对于 angr 来说很难解决的校验检查（例如，其使用 flag 的一些字节来解密数据，并看这些数据是不是合法的 Windows API）。
除此之外，angr 非常适合解决这个问题

[二进制程序](https://github.com/angr/angr-doc/tree/master/examples/whitehatvn2015_re400/re400.exe) 与 [脚本](https://github.com/angr/angr-doc/tree/master/examples/whitehatvn2015_re400/solve.py).

## ReverseMe example: EKOPARTY CTF 2015 - rev 100

作者： Fish Wang (github: @ltfish)

脚本运行时间： 5.5 秒

即使使用 angr 也是一个复杂的问题，应该有更好的解决方式

[二进制程序](https://github.com/angr/angr-doc/tree/master/examples/ekopartyctf2015_rev100/counter) 与 [脚本](https://github.com/angr/angr-doc/tree/master/examples/ekopartyctf2015_rev100/solve.py).

## ReverseMe example: ASIS CTF Finals 2015 - fake

作者： Fish Wang (github: @ltfish)

脚本运行时间： 1 分 57 秒

解决方案简单粗暴

[二进制程序](https://github.com/angr/angr-doc/tree/master/examples/asisctffinals2015_fake/fake) 与 [脚本](https://github.com/angr/angr-doc/tree/master/examples/asisctffinals2015_fake/solve.py).

## ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 100

作者： Fish Wang (github: @ltfish)

几乎不用用户交互，angr 就可以解决这个问题

[脚本](https://github.com/angr/angr-doc/tree/master/examples/defcamp_r100/solve.py) 与 [二进制程序](https://github.com/angr/angr-doc/tree/master/examples/defcamp_r100/r100).

## ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 200

作者： Fish Wang (github: @ltfish)

几乎不用用户交互，angr 就可以解决这个问题。
Veritesting 要求及时检索 flag

[脚本](https://github.com/angr/angr-doc/tree/master/examples/defcamp_r200/solve.py) 与 [二进制程序](https://github.com/angr/angr-doc/tree/master/examples/defcamp_r200/r200)

注意：该脚本在我的电脑上需要运行几分钟

## ReverseMe example: MMA CTF 2015 - HowToUse

作者： Audrey Dutcher (github: @rhelmot)

我们使用 angr 解决了这个问题，因为我们懒得去逆向或者放在 Windows 上去运行它。

[脚本](https://github.com/angr/angr-doc/tree/master/examples/mma_howtouse/solve.py) 展示了我们如何从 [DLL](https://github.com/angr/angr-doc/tree/master/examples/mma_howtouse/howtouse.dll) 中找到 flag


## CrackMe example: MMA CTF 2015 - SimpleHash

作者： Chris Salls (github: @salls)

这个问题的 95% 都可以使用 angr 来解决，但仍然必须手动来解决一些复杂约束

[脚本](https://github.com/angr/angr-doc/tree/master/examples/mma_simplehash/solve.py) 展示了会遇到什么困难，以及是如何解决的。并带有 [二进制程序](https://github.com/angr/angr-doc/tree/master/examples/mma_simplehash/simple_hash).


## ReverseMe example: FlareOn 2015 - Challenge 10

作者： Fish Wang (github: @ltfish)

angr 可以充当二进制加载器与模拟器来解决这个问题。不必将该驱动加载到 Windows 中

[脚本](https://github.com/angr/angr-doc/tree/master/examples/flareon2015_10/solve.py) 展示了如何在任意程序点 Hook 而不影响要执行的预期字节（零长度Hook），以及如何读取内存中的字节并将其解码为字符串

顺便一提，这里还有 FireEye 的[解决方案](https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution10.pdf)


## ReverseMe example: FlareOn 2015 - Challenge 2

作者： Chris Salls (github: @salls)

这个 [二进制程序](https://github.com/angr/angr-doc/tree/master/examples/flareon2015_2/very_success) 使用 angr 就非常容易解决，且比尝试逆向密码校验函数快得多。带有[脚本](https://github.com/angr/angr-doc/tree/master/examples/flareon2015_2/solve.py)


## ReverseMe example: 0ctf 2016 - momo

作者： Fish Wang (github: @ltfish), ocean (github: @ocean1)

在使用 Qira 探索了[二进制程序](https://github.com/xoreaxeaxeax/movfuscator)后想要找到正确的密码。
如何使用 capstone 在二进制程序中找到每个用于校验的字符、如何使用 angr 加载该 [二进制程序](./examples/0ctf_momo/solve.py) 并指定 flag 的单个字符。
请注意：[脚本](./examples/0ctf_momo/solve.py)执行非常慢，运行时间超过一个小时


## CrackMe example: Layer7 CTF 2015 - Windows challenge OnlyOne

作者： Fish Wang (github: @ltfish)

我们在 angr 的帮助下解决了这个问题

[二进制程序](https://github.com/angr/angr-doc/tree/master/examples/layer7_onlyone/onlyone.exe) 与 [脚本](https://github.com/angr/angr-doc/tree/master/examples/layer7_onlyone/solve.py).

脚本演示了：
- 如何加载 Windows 二进制程序文件（与 ELF 程序没有区别）
- 如何使用 Hook 替换加载程序中的任意代码
- 如何使用 Explorer 来执行符号探索（尽管其他人认为 PathGroup 是未来）
- 如何启用 Veritesting，以及这为什么有用


## CrackMe example: 9447 CTF 2015 - Reversing 330, "nobranch"

作者： Audrey Dutcher (github: @rhelmot)

目前 angr 无法解决这个问题，因为这个问题对于 Z3 来说过于复杂了。但将约束条件格式化后，就使得 Z3 能够相对快速的解决问题（求解时我睡着了，所以我不知道花了多长时间！）
[脚本](https://github.com/angr/angr-doc/tree/master/examples/9447_nobranch/solve.py) 与 [二进制程序](https://github.com/angr/angr-doc/tree/master/examples/9447_nobranch/nobranch).

## CrackMe example: ais3_crackme

作者： Antonio Bianchi, Tyler Nighswander

ais3_crackme 由 Tyler Nighswander (tylerni7) 为 ais3 暑期培训而开发。是一个检查命令行参数的简单问题

## ReverseMe: Modern Binary Exploitation - CSCI 4968

作者： David Manouchehri (GitHub [@Manouchehri](https://github.com/Manouchehri))

该[文件夹](https://github.com/angr/angr-doc/tree/master/examples/CSCI-4968-MBE/challenges)含有许多使用 angr 解决问题的脚本。目前只包含 IOLI crackme 套件中的例子，但最终会添加其他解决方案

## CrackMe example: Android License Check

作者： Bernhard Mueller (GitHub [@b-mueller](https://github.com/angr/angr-doc/tree/master/examples/))

为验证命令行参数传递许可证密钥的 [Android/ARM 原生二进制程序](https://github.com/b-angr/angr-doc/tree/master/examples/android_arm_license_validation)问题，其为 [OWASP Mobile Testing Guide](https://github.com/OWASP/owasp-mstg/) 中的符号执行教程而创建
