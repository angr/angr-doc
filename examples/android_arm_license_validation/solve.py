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
    # load_options['ld_path'] = ['/Users/berndt/Tools/android-ndk-r10e/platforms/android-21/arch-arm/usr/lib']

    b = angr.Project("./validate", load_options = load_options)

    # The key validation function starts at 0x401760, so that's where we create the initial state.
    # This speeds things up a lot because we're bypassing the Base32-encoder.

    state = b.factory.blank_state(addr=0x401760)

    concrete_addr = 0xffe00000
    code = claripy.BVS('code', 10*8)
    state.memory.store(concrete_addr, code, endness='Iend_BE')
    state.regs.r0 = concrete_addr

    sm = b.factory.simulation_manager(state)

    # 0x401840 = Product activation passed
    # 0x401854 = Incorrect serial

    sm.explore(find=0x401840, avoid=0x401854)
    found = sm.found[0]

    # Get the solution string from *(R11 - 0x20).

    solution = found.solver.eval(code, cast_to=bytes)

    print(base64.b32encode(solution))
    return code, found

def test():
    user_input, found = main()
    found.solver.add(user_input.get_byte(0) == ord('L'))
    found.solver.add(user_input.get_byte(2) == ord('O'))
    found.solver.add(user_input.get_byte(4) == ord('L'))
    found.solver.add(user_input.get_byte(6) == ord('Z'))
    found.solver.add(user_input.get_byte(8) == ord('!'))
    solution = found.solver.eval(user_input, cast_to=bytes)
    assert found.solver.satisfiable() == True
    # why does b32encode produce bytes and not str? great quesiton!
    assert base64.b32encode(solution) == b'JQAE6ACMABNAAIIA'

if __name__ == '__main__':
    main()
