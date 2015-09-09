# angr examples

To help you get started with angr, we've created several examples.

## Crackme example: Whitehat CTF 2015 - Crypto 400

Author: Yan Shoshitaishvili (github: @Zardus)

We solved this crackme with angr's help.
The resulting script will help you understand how angr can be used for crackme assistance.
You can find this script [here](./examples/whitehat_crypto400/whitehat_crypto400.py) and the binary [here](./examples/whitehat_crypto400/whitehat_crypto400).

## Crackme example: Layer7 CTF 2015 - Windows challenge OnlyOne

Author: Fish Wang (github: @ltfish)

We solved this crackme with angr’s help.
(Fish: This is my first time solving a reversing challenge without understanding what’s going on.)
The challenge binary is [here](./examples/layer7_onlyone/onlyone.exe), and the solving script [here](./examples/layer7_onlyone/solve.py).

The solving script demonstrates the following:
- How to load a Windows binary (no difference than an ELF).
- How to use hook to replace arbitrary code in a loaded program.
- How to use Explorer to perform a symbolic exploration (although everyone else thinks PathGroup is the future).
- How to enable Veritesting, and why it is useful.

## Crackme example: MMA CTF 2015 - SimpleHash

Author: Chris Salls (github: @salls)

This crackme is 95% solveable with angr, but we did have to overcome some difficulties.
The [script](./examples/mma_simplehash/mma_simplehash.py) describes the difficulties that were encountered and how we worked around them.
The binary can be found [here](./examples/mma_simplehash/simple_hash).

## Reverseme example: MMA CTF 2015 - HowToUse

Author: Andrew Dutcher (github: @rhelmot)

We solved this simple reversing challenge with angr, since we were too lazy to reverse it or run it in Windows.
The resulting [script](./examples/mma_howtouse/howtouse.py) shows how we grabbed the flag out of the [DLL](./examples/mma_howtouse/howtouse.dll).
