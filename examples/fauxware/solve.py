#!/usr/bin/env python

import angr

# Look at fauxware.c! This is the source code for a "faux firmware" (@zardus
# really likes the puns) that's meant to be a simple representation of a
# firmware that can authenticate users but also has a backdoor - the backdoor
# is that anybody who provides the string "SOSNEAKY" as their password will be
# automatically authenticated.


def basic_symbolic_execution():
    # We can use this as a basic demonstration of using angr for symbolic
    # execution. First, we load the binary into an angr project.

    p = angr.Project('fauxware')

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

    # States are relatively static objects, they don't do anything "smart".
    # You can read data into and out of them, but that's about it.
    # In order to actually perform symbolic execution, you need a Path.
    # Paths wrap states and are your interface for stepping them forward and
    # tracking their history.

    path = p.factory.path(state)

    # Now, in order to manage the symbolic execution process from a very high
    # level, we have a PathGroup. Path groups are just collections of paths
    # with various tags attached with a number of convenient interfaces for
    # managing them.

    pathgroup = p.factory.path_group(path)

    # Uncomment the following line to spawn an IPython shell when the program
    # gets to this point so you can poke around at the four objects we just
    # constructed. Use tab-autocomplete and IPython's nifty feature where if
    # you stick a question mark after the name of a function or method and hit
    # enter, you are shown the documentation string for it.

    # import IPython; IPython.embed()

    # Now, we begin execution. This will symbolically execute the program until
    # we reach a branch statement for which both branches are satisfiable.

    pathgroup.step(until=lambda lpg: len(lpg.active) > 1)

    # If you look at the C code, you see that the first "if" statement that the
    # program can come across is comparing the result of the strcmp with the
    # backdoor password. So, we have halted execution with two states, each of
    # which has taken a different arm of that conditional branch. If you drop
    # an IPython shell here and examine pathgroup.active[n].state.se.constraints
    # you will see the encoding of the condition that was added to the state to
    # constrain it to going down this path, instead of the other one. These are
    # the constraints that will eventually be passed to our constraint solver
    # (z3) to produce a set of concrete inputs satisfying them.

    # As a matter of fact, we'll do that now.

    input_0 = pathgroup.active[0].state.posix.dumps(0)
    input_1 = pathgroup.active[1].state.posix.dumps(0)

    # We have used a utility function on the state's posix plugin to perform a
    # quick and dirty concretization of the content in file descriptor zero,
    # stdin. One of these strings should contain the substring "SOSNEAKY"!

    if 'SOSNEAKY' in input_0:
        return input_0
    else:
        return input_1

def test():
    pass        # appease our CI infrastructure which expects this file to do something lmao

if __name__ == '__main__':
    print basic_symbolic_execution()

# You should be able to run this program and pipe its into fauxware in order to
# produce a "sucessfully authenticated" message
