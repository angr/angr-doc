# angr examples

To help you get started with [angr](https://github.com/angr/angr), we've created several examples.
These mostly stem from CTF problems solved with angr by Shellphish.
Enjoy!

## ReverseMe example: WhiteHat Grant Prix Global Challenge 2015 - Re400

Author: Fish Wang (github: @ltfish)

Script runtime: 5.5 sec

A Windows binary that takes a flag as argument, and tells you if the flag is correct or not.

I have to patch out some checks that are difficult for angr to solve (e.g. it uses some bytes of the flag to decrypt some data, and see if those data are legit Windows APIs). 
Other than that, angr works really well for solving this challenge.

The [binary](./examples/whitehatvn2015_re400/re400.exe) and the [script](./examples/whitehatvn2015_re400/solve.py). 
Enjoy!

## ReverseMe example: EKOPARTY CTF 2015 - rev 100

Author: Fish Wang (github: @ltfish)

Script runtime: 5.5 sec

This is a painful challenge to solve with angr. I should have done things in a smarter way.

Here is the [binary](./examples/ekopartyctf2015_rev100/counter) and the [script](./examples/ekopartyctf2015_rev100/solve.py).

## ReverseMe example: ASIS CTF Finals 2015 - fake

Author: Fish Wang (github: @ltfish)

Script runtime: 1 min 57 sec

The solution is pretty straight-forward.

The [binary](./examples/asisctffinals2015_fake/fake) and the [script](./examples/asisctffinals2015_fake/solve.py).

## ReverseMe example: ASIS CTF Finals 2015 - license

Author: Fish Wang (github: @ltfish)

Script runtime: 3.6 sec

This is a good example that showcases the following:

- Create a custom file, and load it during symbolic execution.
- Create an inline call to SimProcedure `strlen`, and use it to determine the length of a string in memory - even if the string may not be null-terminated.
- `LAZY_SOLVES` should be disabled sometimes to avoid creating too many paths.

Here are the [binary](./examples/asisctffinals2015_license/license) and the [script](./examples/asisctffinals2015_license/solve.py).

## ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 100

Author: Fish Wang (github: @ltfish)

Angr solves this challenge with almost zero user-interference.

See the [script](./examples/defcamp_r100/solve.py) and the [binary](./examples/defcamp_r100/r100).

## ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 200

Author: Fish Wang (github: @ltfish)

Angr solves this challenge with almost zero user-interference. Veritesting is required to retrieve the flag promptly.

The [script](./examples/defcamp_r200/solve.py) and the [binary](./examples/defcamp_r200/r200).
It takes a few minutes to run on my laptop.

## ReverseMe example: MMA CTF 2015 - HowToUse

Author: Andrew Dutcher (github: @rhelmot)

We solved this simple reversing challenge with angr, since we were too lazy to reverse it or run it in Windows.
The resulting [script](./examples/mma_howtouse/solve.py) shows how we grabbed the flag out of the [DLL](./examples/mma_howtouse/howtouse.dll).


## CrackMe example: MMA CTF 2015 - SimpleHash

Author: Chris Salls (github: @salls)

This crackme is 95% solveable with angr, but we did have to overcome some difficulties.
The [script](./examples/mma_simplehash/solve.py) describes the difficulties that were encountered and how we worked around them.
The binary can be found [here](./examples/mma_simplehash/simple_hash).


## ReverseMe example: FlareOn 2015 - Challenge 10

Author: Fish Wang (github: @ltfish)

angr acts as a binary loader and an emulator in solving this challenge. 
I didn’t have to load the driver onto my Windows box.

The [script](./examples/flareon2015_10/solve.py) demonstrates how to hook at arbitrary program points without affecting the intended bytes to be executed (a zero-length hook). 
It also shows how to read bytes out of memory and decode as a string.

By the way, here is the [link](https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution10.pdf) to the intended solution from FireEye.


## ReverseMe example: FlareOn 2015 - Challenge 2

Author: Chris Salls (github: @salls)

This [reversing challenge](./examples/flareon2015_2/very_success) is simple to solve almost entirely with angr, and a lot faster than trying to reverse the password checking function. The script is [here](./examples/flareon2015_2/solve.py)


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
You can find this script [here](./examples/whitehat_crypto400/solve.py) and the binary [here](./examples/whitehat_crypto400/whitehat_crypto400).

## CrackMe example: CSAW CTF 2015 Quals - Reversing 500, "wyvern"

Author: Andrew Dutcher (github: @rhelmot)

Angr can outright solve this challenge with very little assistance from the user.
The script to do so is [here](./examples/csaw_wyvern/solve.py) and the binary is [here](./examples/csaw_wyvern/wyvern).

## CrackMe example: 9447 CTF 2015 - Reversing 330, "nobranch"

Author: Andrew Dutcher (github: @rhelmot)

Angr cannot currently solve this problem naively, as the problem is too complex for z3 to solve.
Formatting the constraints to z3 a little differently allows z3 to come up with an answer relatively quickly. (I was asleep while it was solving, so I don't know exactly how long!)
The script for this is [here](./examples/9447_nobranch/solve.py) and the binary is [here](./examples/9447_nobranch/nobranch).
