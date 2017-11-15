#!/usr/bin/python

'''
Quick-and-dirty solution for the (un-obfuscated) Android License Check crackme from the Obfuscation Metrics Project.
The full how-to can be found in the 'Android' section of the OWASP Mobile Security Testing Guide:

https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06a-Reverse-Engineering-and-Tampering-Android.md

'''

import angr
import claripy
import base64

def main():
    load_options = {}

    # Android NDK library path:
    # load_options['custom_ld_path'] = ['/Users/berndt/Tools/android-ndk-r10e/platforms/android-21/arch-arm/usr/lib']

    b = angr.Project("./validate", load_options = load_options)

    # The key validation function starts at 0x401760, so that's where we create the initial state.
    # This speeds things up a lot because we're bypassing the Base32-encoder.

    state = b.factory.blank_state(addr=0x401760)

    sm = b.factory.simulation_manager(state)

    # 0x401840 = Product activation passed
    # 0x401854 = Incorrect serial

    sm.explore(find=0x401840, avoid=0x401854)
    found = sm.found[0]

    # Get the solution string from *(R11 - 0x24).

    addr = found.memory.load(found.regs.r11 - 0x24, endness='Iend_LE')
    concrete_addr = found.solver.eval(addr)
    solution = found.solver.eval(found.memory.load(concrete_addr,10), cast_to=str)

    return base64.b32encode(solution)

def test():
    print "TEST MODE"
#   assert main() == 'JQAE6ACMABNAAIIA'
    print main()

if __name__ == '__main__':
    print main()
