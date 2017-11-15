#!/usr/bin/env python

'''
CADET_00001 is one of the challenge released by DARPA for the Cyber Grand Challenge:
https://github.com/CyberGrandChallenge/samples/tree/master/examples/CADET_00001

The binary can run in the DECREE VM (http://repo.cybergrandchallenge.com/boxes/)

CADET_00001.adapted (by Jacopo Corbetta) is the same program, modified to be runnable in an Intel x86 Linux machine.

The binary contains an easter egg and a stack buffer overflow.
'''

import angr


def main():
    project= angr.Project("./CADET_00001")

    #let's find the buffer overflow (overwriting the return address)
    #overwriting the return pointer with user-controllable data will generate
    #an "unconstrained" state: the symbolic executor does not know how to proceed
    #since the instruction pointer can assume any value

    #by default angr discards unconstrained paths, so we need to specify the  
    #save_unconstrained option
    print "finding the buffer overflow..."
    sm = project.factory.simulation_manager(save_unconstrained=True)
    #symbolically execute the binary until an unconstrained path is reached
    while len(sm.unconstrained)==0:
        sm.step()
    unconstrained_state = sm.unconstrained[0]
    crashing_input = unconstrained_state.posix.dumps(0)
    #cat crash_input.bin | ./CADET_00001.adapted will segfault
    unconstrained_state.posix.dump(0,"crash_input.bin")
    print "buffer overflow found!"
    print repr(crashing_input)


    #let's now find the easter egg (it takes about 2 minutes)

    #now we want angr to avoid "unfeasible" paths
    #by default, "lazy solving" is enabled, this means that angr will not 
    #automatically discard unfeasible paths

    #to disable "lazy solving" we generate a blank path and we change its options,
    #then we specify this path as the initial path of the path group
    print "finding the easter egg..."
    sm = project.factory.simulation_manager(project.factory.entry_state())

    #at this point we just ask angr to reach the basic block where the easter egg 
    #text is printed
    sm.explore(find=0x804833E)
    found = sm.found[0]
    solution1 = found.posix.dumps(0)
    print "easter egg found!"
    print repr(solution1)
    found.posix.dump(0,"easteregg_input1.bin")
    #you can even check if the easter egg has been found by checking stdout
    stdout1 = found.posix.dumps(1)
    print repr(stdout1)

    #an alternative way to avoid unfeasible paths (paths that contain an unsatisfiable set
    #of constraints) is to "manually" step the path group execution and call prune()
    print "finding the easter egg (again)..."
    sm = project.factory.simulation_manager()
    while True:
        sm.step()
        sm.prune() #we "manually" ask angr to remove unfeasible paths 
        found_list = [active for active in sm.active if active.addr == 0x804833E]
        if len(found_list) > 0:
            break
    found = found_list[0]
    solution2 = found.posix.dumps(0)
    print "easter egg found!"
    print repr(solution2)
    found.posix.dump(0,"easteregg_input2.bin")
    #you can even check if the easter egg has been found by checking stdout
    stdout2 = found.posix.dumps(1)
    print repr(stdout2)

    return (crashing_input, solution1, stdout1, solution2, stdout2)


def test():
    crashing_input, solution1, stdout1, solution2, stdout2 = main()
    assert len(crashing_input) >= 92 and solution1.startswith("^") and solution2.startswith("^") and \
            "EASTER EGG!" in stdout1 and "EASTER EGG!" in stdout2


if __name__ == '__main__':
    print(repr(main()))


