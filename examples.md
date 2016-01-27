# angr examples

To help you get started with [angr](https://github.com/angr/angr), we've created several examples.
These mostly stem from CTF problems solved with angr by Shellphish.
Enjoy!

## Introduction example - Fauxware

This is a basic script that explains how to use angr to symbolically execute a program and produce concrete input satisfying certain conditions.

Binary, source, and script are found [here.](./examples/fauxware)

## CTF Problems
### ReverseMe example: WhiteHat Grant Prix Global Challenge 2015 - Re400

Author: Fish Wang (github: @ltfish)

Script runtime: 5.5 sec

A Windows binary that takes a flag as argument, and tells you if the flag is correct or not.

I have to patch out some checks that are difficult for angr to solve (e.g. it uses some bytes of the flag to decrypt some data, and see if those data are legit Windows APIs). 
Other than that, angr works really well for solving this challenge.

The [binary](./examples/whitehatvn2015_re400/re400.exe) and the [script](./examples/whitehatvn2015_re400/solve.py). 
Enjoy!

### ReverseMe example: EKOPARTY CTF 2015 - rev 100

Author: Fish Wang (github: @ltfish)

Script runtime: 5.5 sec

This is a painful challenge to solve with angr. I should have done things in a smarter way.

Here is the [binary](./examples/ekopartyctf2015_rev100/counter) and the [script](./examples/ekopartyctf2015_rev100/solve.py).

### ReverseMe example: ASIS CTF Finals 2015 - fake

Author: Fish Wang (github: @ltfish)

Script runtime: 1 min 57 sec

The solution is pretty straight-forward.

The [binary](./examples/asisctffinals2015_fake/fake) and the [script](./examples/asisctffinals2015_fake/solve.py).

### ReverseMe example: ASIS CTF Finals 2015 - license

Author: Fish Wang (github: @ltfish)

Script runtime: 3.6 sec

This is a good example that showcases the following:

- Create a custom file, and load it during symbolic execution.
- Create an inline call to SimProcedure `strlen`, and use it to determine the length of a string in memory - even if the string may not be null-terminated.
- `LAZY_SOLVES` should be disabled sometimes to avoid creating too many paths.

Here are the [binary](./examples/asisctffinals2015_license/license) and the [script](./examples/asisctffinals2015_license/solve.py).

### ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 100

Author: Fish Wang (github: @ltfish)

angr solves this challenge with almost zero user-interference.

See the [script](./examples/defcamp_r100/solve.py) and the [binary](./examples/defcamp_r100/r100).

### ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 200

Author: Fish Wang (github: @ltfish)

angr solves this challenge with almost zero user-interference. Veritesting is required to retrieve the flag promptly.

The [script](./examples/defcamp_r200/solve.py) and the [binary](./examples/defcamp_r200/r200).
It takes a few minutes to run on my laptop.

### ReverseMe example: MMA CTF 2015 - HowToUse

Author: Andrew Dutcher (github: @rhelmot)

We solved this simple reversing challenge with angr, since we were too lazy to reverse it or run it in Windows.
The resulting [script](./examples/mma_howtouse/solve.py) shows how we grabbed the flag out of the [DLL](./examples/mma_howtouse/howtouse.dll).


### CrackMe example: MMA CTF 2015 - SimpleHash

Author: Chris Salls (github: @salls)

This crackme is 95% solveable with angr, but we did have to overcome some difficulties.
The [script](./examples/mma_simplehash/solve.py) describes the difficulties that were encountered and how we worked around them.
The binary can be found [here](./examples/mma_simplehash/simple_hash).


### ReverseMe example: FlareOn 2015 - Challenge 10

Author: Fish Wang (github: @ltfish)

angr acts as a binary loader and an emulator in solving this challenge. 
I didn’t have to load the driver onto my Windows box.

The [script](./examples/flareon2015_10/solve.py) demonstrates how to hook at arbitrary program points without affecting the intended bytes to be executed (a zero-length hook). 
It also shows how to read bytes out of memory and decode as a string.

By the way, here is the [link](https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution10.pdf) to the intended solution from FireEye.


### ReverseMe example: FlareOn 2015 - Challenge 2

Author: Chris Salls (github: @salls)

This [reversing challenge](./examples/flareon2015_2/very_success) is simple to solve almost entirely with angr, and a lot faster than trying to reverse the password checking function. The script is [here](./examples/flareon2015_2/solve.py)


### ReverseMe example: FlareOn 2015 - Challenge 5

Author: Adrian Tang (github: @tangabc)

Script runtime: 2 mins 10 secs

This is another [reversing challenge](./examples/flareon2015_5/sender) from the FlareOn challenges.

"The challenge is designed to teach you about PCAP file parsing and traffic decryption by
reverse engineering an executable used to generate it. This is a typical scenario in our
malware analysis practice where we need to figure out precisely what the malware was doing
on the network"

For this challenge, the author used angr to represent the desired encoded output as a series of contraints for the SAT solver to solve for the input.

For a detailed write-up please visit the author's post [here](http://0x0atang.github.io/reversing/2015/09/18/flareon5-concolic.html) and
you can also find the solution from the FireEye [here](https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution5.pdf)



### CrackMe example: Layer7 CTF 2015 - Windows challenge OnlyOne

Author: Fish Wang (github: @ltfish)

We solved this crackme with angr’s help.
(Fish: This is my first time solving a reversing challenge without understanding what’s going on.)
The challenge binary is [here](./examples/layer7_onlyone/onlyone.exe), and the solving script [here](./examples/layer7_onlyone/solve.py).

The solving script demonstrates the following:
- How to load a Windows binary (no difference than an ELF).
- How to use hook to replace arbitrary code in a loaded program.
- How to use Explorer to perform a symbolic exploration (although everyone else thinks PathGroup is the future).
- How to enable Veritesting, and why it is useful.


### CrackMe example: Whitehat CTF 2015 - Crypto 400

Author: Yan Shoshitaishvili (github: @Zardus)

We solved this crackme with angr's help.
The resulting script will help you understand how angr can be used for crackme assistance.
You can find this script [here](./examples/whitehat_crypto400/solve.py) and the binary [here](./examples/whitehat_crypto400/whitehat_crypto400).

### CrackMe example: CSAW CTF 2015 Quals - Reversing 500, "wyvern"

Author: Andrew Dutcher (github: @rhelmot)

angr can outright solve this challenge with very little assistance from the user.
The script to do so is [here](./examples/csaw_wyvern/solve.py) and the binary is [here](./examples/csaw_wyvern/wyvern).

### CrackMe example: 9447 CTF 2015 - Reversing 330, "nobranch"

Author: Andrew Dutcher (github: @rhelmot)

angr cannot currently solve this problem naively, as the problem is too complex for z3 to solve.
Formatting the constraints to z3 a little differently allows z3 to come up with an answer relatively quickly. (I was asleep while it was solving, so I don't know exactly how long!)
The script for this is [here](./examples/9447_nobranch/solve.py) and the binary is [here](./examples/9447_nobranch/nobranch).

### CrackMe example: ais3_crackme

Author: Antonio Bianchi, Tyler Nighswander

ais3_crackme has been developed by Tyler Nighswander (tylerni7) for ais3 summer school. It is an easy crackme challenge, checking its command line argument.

## Exploitation Examples
### Beginner Exploitation example: strcpy_find

Author: Kyle Ossinger (github: @k0ss)

This is the first in a series of "tutorial scripts" I'll be making which use angr to find exploitable conditions in binaries.  The first example is a very simple program.  The script finds a path from the main entry point to `strcpy`, but **only** when we control the source buffer of the `strcpy` operation.  To hit the right path, angr has to solve for a password argument, but angr solved this in less than 2 seconds on my machine using the standard python interpreter.  The script might look large, but that's only because I've heavily commented it to be more helpful to beginners.  The challenge binary is [here](./examples/strcpy_find/strcpy_test') and the script is [here](./examples/strcpy_find/solve.py).

### Beginner Exploitation example: CADET_0001
Author: Antonio Bianchi, Jacopo Corbetta

This is a very easy binary containing a stack buffer overflow and an easter egg.
CADET_00001 is one of the challenge released by DARPA for the Cyber Grand Challenge:
[link](https://github.com/CyberGrandChallenge/samples/tree/master/examples/CADET_00001)
The binary can run in the DECREE VM: [link](http://repo.cybergrandchallenge.com/boxes/)
CADET_00001.adapted (by Jacopo Corbetta) is the same program, modified to be runnable in an Intel x86 Linux machine.

### Grub "back to 28" bug

Author: Andrwe Dutcher (github: @rhelmot)

This is the demonstration presented at 32c3. The script uses angr to discover the input to crash grub's password entry prompt.

[script](./examples/grub/solve.py) - [vulnerable module](./examples/grub/crypto.mod)
