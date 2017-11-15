#import logging
#
#logging.getLogger('angr.surveyors.explorer').setLevel(logging.DEBUG)
#logging.getLogger('angr.surveyor').setLevel(logging.DEBUG)
#logging.getLogger('angr.analyses.veritesting').setLevel(logging.DEBUG)

"""
This is an example that uses angr to solve a challenge from Layer7 CTF 2015.
"""

import angr
import logging

def decrypt(state):
    buf = state.regs.edx # The second argument
    # Skipped the real decryption procedure, and write the final string there instead
    # I'm lazy :-)
    state.memory.store(buf, state.solver.BVV(int('layerseven\x00'.encode('hex'), 16), 88))

def main():
    # Load the project
    p = angr.Project("onlyone.exe", use_sim_procedures=True)
    # Hook the malloc - we cannot automatically use SimProcedures for it, which will be fixed soon
    p.hook(0x2398, angr.SIM_PROCEDURES['libc']['malloc'])
    # Hook the decrypt function merely because we don't support pow/sqrt/floor
    p.hook(0x401038, decrypt, length=5)

    # This is the content in 'encrypted' file
    # Our input string should be encrypted to this string
    encrypted = "253e315126363a2e551c".decode('hex')

    # Create the initial state starting from the target function
    initial_state = p.factory.blank_state(addr=0x401000)

    # Where our input string comes from
    str_ptr = 0x800000

    # Load our input string, and make sure there is no null byte inside
    content = initial_state.memory.load(str_ptr, len(encrypted))
    for i in xrange(0, len(content), 8):
        initial_state.add_constraints(content[i + 7 : i] != 0)

    # Make sure the input string ends with a null byte
    zero = initial_state.memory.load(str_ptr + len(encrypted), 1)
    initial_state.add_constraints(zero == 0)

    # Push the str_ptr onto stack
    initial_state.stack_push(initial_state.solver.BVV(str_ptr, 32))
    # Push a return address
    initial_state.stack_push(initial_state.solver.BVV(0, 32))

    # Create the initial path

    # Call explorer to execute the function
    # Note that Veritesting is important since we want to avoid unnecessary branching
    ex = angr.surveyors.Explorer(p, start=initial_state, find=(0x4010c9, ), enable_veritesting=True)
    print "Executing..."
    angr.surveyors.explorer.l.setLevel(logging.DEBUG)
    angr.surveyors.surveyor.l.setLevel(logging.DEBUG)
    r = ex.run()

    if r.found:
        final_state = r.found[0]
    else:
        final_state = r.errored[0].previous_run.initial_state

    # Load the final encrypted string, add constraints to make the string be equal to encrypted data
    buf_ptr = final_state.memory.load(final_state.regs.ebp - 0x18, 4, endness=p.arch.memory_endness)
    for i in xrange(0, len(encrypted)):
        final_state.add_constraints(final_state.memory.load(buf_ptr + i, 1) == ord(encrypted[i]))

    # Our input - solve it!
    input_string = final_state.memory.load(str_ptr, 10)
    print "Solving..."
    candidates = final_state.solver.eval_upto(input_string, 2)

    assert len(candidates) == 1
    return hex(candidates[0])[2 : -1].decode('hex')

def test():
    assert main() == 'I_H4TE_X0r'

if __name__ == "__main__":
    print main()
