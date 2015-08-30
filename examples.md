# angr examples

To help you get started with angr, we've created several examples.

## Crackme example: Whitehat CTF 2015 Crypto 400

We solved this crackme with angr's help.
The resulting script will help you understand how angr can be used for crackme assistance.
You can find this script [here](./examples/whitehat_crypto400/whitehat_crypto400.py) and the binary [here](./examples/whitehat_crypto400/whitehat_crypto400).

## Crackme example: Layer7 CTF 2015 Windows challenge OnlyOne

We solved this crackme with angr’s help.
(Fish: This is my first time solving a reversing challenge without understanding what’s going on.)
The challenge binary is [here](./examples/layer7_onlyone/onlyone.exe), and the solving script [here](./examples/layer7_onlyone/solve.py).

The solving script demonstrates the following:
- How to load a Windows binary (no difference than an ELF).
- How to use hook to replace arbitrary code in a loaded program.
- How to use Explorer to perform a symbolic exploration (although everyone else thinks PathGroup is the future).
- How to enable Veritesting, and why it is useful.

