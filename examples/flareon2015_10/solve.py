import logging

import angr
from angr.sim_type import SimTypeFunction, SimTypeInt
from angr.procedures.stubs.UserHook import UserHook

# This is literally how I solved this challenge during the game. Now I know it's easier
# to just call tea_decrypt with those bytes (and the correct key), but I don't want to
# change this script anymore.

# You are strongly recommended to use pypy to run this script in order to get a better
# performance.

# I would like to thank my girlfriend for allowing me to work on FlareOn challenges
# during several nights we spent together.

ARRAY_ADDRESS = 0x29f210
BIG_PROC = 0x2d2e0

def before_tea_decrypt(state):
    # Here we want to set the value of the byte array starting from 0x29f210
    # I got those bytes by using cross-reference in IDA
    all_bytes = [0x56, 0x7f, 0xdc, 0xfa, 0xaa, 0x27, 0x99, 0xc4, 0x6c, 0x7c,
             0xfc, 0x92, 0x61, 0x61, 0x47, 0x1a, 0x19, 0xb9, 0x63, 0xfd,
             0xc, 0xf2, 0xb6, 0x20, 0xc0, 0x2d, 0x5c, 0xfd, 0xd9, 0x71,
             0x54, 0x96, 0x4f, 0x43, 0xf7, 0xff, 0xbb, 0x4c, 0x5d, 0x31]
    mem_bytes = "".join([ chr(i) for i in all_bytes ])
    state.memory.store(ARRAY_ADDRESS, mem_bytes)

def main():
    p = angr.Project('challenge-7.sys', load_options={'auto_load_libs': False})

    # Set a zero-length hook, so our function got executed before calling the
    # function tea_decrypt(0x100f0), and then we can keep executing the original
    # code. Thanks to this awesome design by @rhelmot!
    p.hook(0xadc31, before_tea_decrypt, length=0)

    # Declare the prototype of the target function
    prototype = SimTypeFunction((SimTypeInt(False),), SimTypeInt(False))
    # Initialize the function instance
    proc_big_68 = p.factory.callable(BIG_PROC, cc=p.factory.cc(func_ty=prototype), toc=None, concrete_only=True)
    # Call the function and get the final state
    proc_big_68.perform_call(0)
    state = proc_big_68.result_state
    # Load the string from memory
    return hex(state.solver.eval(state.memory.load(ARRAY_ADDRESS, 40)))[2:-1].decode('hex').strip('\0')

def test():
    assert main() == "unconditional_conditions@flare-on.com"

if __name__ == "__main__":
    # Turn on logging so we know what's going on...
    # It's up to you to set up a logging handler beforehand
    logging.getLogger('angr.manager').setLevel(logging.DEBUG)
    print main()
