import angr
import sys
import logging

# HackCon 2016 - angry-reverser
# @author: P1kachu
# @contact: p1kachu@lse.epita.fr
# Execution time: ~31 minutes - Intel Core i7-3770 CPU @ 3.40GHz (8 CPUs)


def main():
    p = angr.Project('yolomolo')

    main        = 0x405a6f # Fail message to be printed
    find        = 0x405aee # Win message printed
    avoid       = (0x405af0, 0x405ab4) # First two ways to fail from main
    crazy       = 0x400646 # Entry point of Crazy function

    # Offset (from IDA) of 'FAIL' blocks in Crazy
    fails = [0x2619, 0x288C, 0x2AF9, 0x2D68, 0x2FD5, 0x3245, 0x34B2,
             0x3724, 0x3996, 0x3C04, 0x3E73, 0x40E7, 0x4355, 0x45C9,
             0x4836, 0x4AA4, 0x4D15, 0x4F86, 0x51D1, 0x5408]

    # Create blank state with $pc at &main
    init = p.factory.blank_state(addr=main)

    # Avoid blocks
    avoid = list(avoid)
    avoid += [(crazy + offst) for offst in fails] # Let's save RAM

    print("Launching exploration")
    sm = p.factory.simulation_manager(init, threads=8)
    angr.manager.l.setLevel(logging.DEBUG)
    ex = sm.explore(find=find, avoid=avoid)

    # Get stdout
    final = ex.found[0]
    flag = final.posix.dumps(1)
    print("Flag: {0}".format(final.posix.dumps(1)))

    return flag[7:27]

def test():
    assert main() == "HACKCON{VVhYS04ngrY}"

if __name__ in '__main__':
    assert main() == "HACKCON{VVhYS04ngrY}"
