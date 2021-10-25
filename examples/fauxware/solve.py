#!/usr/bin/env python

import angr
import sys

# Look at fauxware.c! This is the source code for a "faux firmware" (@zardus
# really likes the puns) that's meant to be a simple representation of a
# firmware that can authenticate users but also has a backdoor - the backdoor
# is that anybody who provides the string "SOSNEAKY" as their password will be
# automatically authenticated.


def basic_symbolic_execution():
    # We can use this as a basic demonstration of using angr for symbolic
    # execution. First, we load the binary into an angr project.

    p = angr.Project('fauxware', auto_load_libs=False)

    # Now, we want to construct a representation of symbolic program state.
    # SimState objects are what angr manipulates when it symbolically executes
    # binary code.
    # The entry_state constructor generates a SimState that is a very generic
    # representation of the possible program states at the program's entry
    # point. There are more constructors, like blank_state, which constructs a
    # "blank slate" state that specifies as little concrete data as possible,
    # or full_init_state, which performs a slow and pedantic initialization of
    # program state as it would execute through the dynamic loader.

    state = p.factory.entry_state()

    # Now, in order to manage the symbolic execution process from a very high
    # level, we have a SimulationManager. SimulationManager is just collections
    # of states with various tags attached with a number of convenient
    # interfaces for managing them.

    sm = p.factory.simulation_manager(state)

    # Uncomment the following line to spawn an IPython shell when the program
    # gets to this point so you can poke around at the four objects we just
    # constructed. Use tab-autocomplete and IPython's nifty feature where if
    # you stick a question mark after the name of a function or method and hit
    # enter, you are shown the documentation string for it.

    # import IPython; IPython.embed()

    # Now, we begin execution. This will symbolically execute the program until
    # we reach a branch statement for which both branches are satisfiable.

    sm.run(until=lambda sm_: len(sm_.active) > 1)

    # If you look at the C code, you see that the first "if" statement that the
    # program can come across is comparing the result of the strcmp with the
    # backdoor password. So, we have halted execution with two states, each of
    # which has taken a different arm of that conditional branch. If you drop
    # an IPython shell here and examine sm.active[n].solver.constraints
    # you will see the encoding of the condition that was added to the state to
    # constrain it to going down this path, instead of the other one. These are
    # the constraints that will eventually be passed to our constraint solver
    # (z3) to produce a set of concrete inputs satisfying them.

    # As a matter of fact, we'll do that now.

    input_0 = sm.active[0].posix.dumps(0)
    input_1 = sm.active[1].posix.dumps(0)

    # We have used a utility function on the state's posix plugin to perform a
    # quick and dirty concretization of the content in file descriptor zero,
    # stdin. One of these strings should contain the substring "SOSNEAKY"!

    if b'SOSNEAKY' in input_0:
        return input_0
    else:
        return input_1

def test():
    r = basic_symbolic_execution()
    assert b'SOSNEAKY' in r

if __name__ == '__main__':
    sys.stdout.buffer.write(basic_symbolic_execution())

# You should be able to run this script and pipe its output to fauxware and
# fauxware will authenticate you.
