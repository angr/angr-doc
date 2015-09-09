# angr examples

To help you get started with [angr](https://github.com/angr/angr), we've created several examples.
These mostly stem from CTF problems solved with angr by Shellphish.
Enjoy!


## ReverseMe example: MMA CTF 2015 - HowToUse

Author: Andrew Dutcher (github: @rhelmot)

We solved this simple reversing challenge with angr, since we were too lazy to reverse it or run it in Windows.
The resulting [script](./examples/mma_howtouse/howtouse.py) shows how we grabbed the flag out of the [DLL](./examples/mma_howtouse/howtouse.dll).


## CrackMe example: MMA CTF 2015 - SimpleHash

Author: Chris Salls (github: @salls)

This crackme is 95% solveable with angr, but we did have to overcome some difficulties.
The [script](./examples/mma_simplehash/mma_simplehash.py) describes the difficulties that were encountered and how we worked around them.
The binary can be found [here](./examples/mma_simplehash/simple_hash).


## ReverseMe example: FlareOn 2015 - Challenge 10

Author: Fish Wang (github: @ltfish)

angr acts as a binary loader and an emulator in solving this challenge. 
I didn’t have to load the driver onto my Windows box.

The [script](./examples/flareon2015_10/flareon-solution-10.py) demonstrates how to hook at arbitrary program points without affecting the intended bytes to be executed (a zero-length hook). 
It also shows how to read bytes out of memory and decode as a string.

By the way, here is the [link](https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution10.pdf) to the intended solution from FireEye.


## ReverseMe example: FlareOn 2015 - Challenge 2

Author: Chris Salls (github: @salls)

This [reversing challenge](./examples/flareon2015_2/very_success) is simple to solve almost entirely with angr, and a lot faster than trying to reverse the password checking function. The script is [here](./examples/flareon2015_2/flareon-solution-2.py)


## CrackMe example: Layer7 CTF 2015 - Windows challenge OnlyOne

Author: Fish Wang (github: @ltfish)

We solved this crackme with angr’s help.
(Fish: This is my first time solving a reversing challenge without understanding what’s going on.)
The challenge binary is [here](./examples/layer7_onlyone/onlyone.exe), and the solving script [here](./examples/layer7_onlyone/solve.py).

The solving script demonstrates the following:
- How to load a Windows binary (no difference than an ELF).
- How to use hook to replace arbitrary code in a loaded program.
- How to use Explorer to perform a symbolic exploration (although everyone else thinks PathGroup is the future).
- How to enable Veritesting, and why it is useful.


## CrackMe example: Whitehat CTF 2015 - Crypto 400

Author: Yan Shoshitaishvili (github: @Zardus)

We solved this crackme with angr's help.
The resulting script will help you understand how angr can be used for crackme assistance.
You can find this script [here](./examples/whitehat_crypto400/whitehat_crypto400.py) and the binary [here](./examples/whitehat_crypto400/whitehat_crypto400).
