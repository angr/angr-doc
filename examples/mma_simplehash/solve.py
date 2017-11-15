#!/usr/bin/env python

#
# simple_hash was a reversing challenge in the first MMA CTF, held in 2015.
# This binary implemented a hash function. To get the flag, the hacker needed
# to provide an input that hashed to a specific value.
#
# This provided a number of challenges to angr:
#
# 1. Because we need to automatically break a hash, constraint solves can be
#    extremely slow. This means that we need to adjust Z3's timeout so that
#    constraint solves will succeed.
# 2. The optimized way in which modular multiplication is implemented in the
#    binary causes problems for angr's symbolic execution engine and results
#    in a path explosion. To get around this, we need to hook the `mm` and
#    `moddi3` functions with python summaries.
# 3. There is a bug in angr's environment model, causing global data used by
#    `isalnum` to be improperly initialized. As a temporary fix, we need to
#    hook the `isalnum` function with a python summary.
# 4. One of the initializers in the binary causes a path explosion in the
#    symbolic execution engine. This is also likely due to a faulty environment
#    model. Our solution was to simply begin execution from within `main()`,
#    manually specifying the user input.
#
# Once these issues are addressed, things go fairly smoothly! Keep in mind that
# this is still a tough problem for symbolic execution, so the solution takes
# about an hour to run.

#
# Go go go!
#

import angr

#
# These are our symbolic summary functions for modular multiplication, modulo,
# and isalnum.
#

class mm(angr.SimProcedure):
    def run(self, low1, high1, low2, high2):
        first = high1.concat(low1)
        second = high2.concat(low2)
        result = (first * second) % 1000000000000037
        self.state.regs.edx = self.state.solver.Extract(63, 32, result)
        return self.state.solver.Extract(31, 0, result)

class moddi3(angr.SimProcedure):
    def run(self, a, a2, b, b2):
        first = a2.concat(a)
        second = b2.concat(b)
        result = first % second
        self.state.regs.edx = self.state.solver.Extract(63, 32, result)
        return self.state.solver.Extract(31, 0, result)

class isalnum(angr.SimProcedure):
    def run(self, c):
        is_num = self.state.solver.And(c >= ord("0"), c <= ord("9"))
        is_alpha_lower = self.state.solver.And(c >= ord("a"), c <= ord("z"))
        is_alpha_upper = self.state.solver.And(c >= ord("A"), c <= ord("Z"))
        isalphanum = self.state.solver.Or(is_num, is_alpha_lower, is_alpha_upper)
        return self.state.solver.If(isalphanum, self.state.solver.BVV(1, self.state.arch.bits), self.state.solver.BVV(0, self.state.arch.bits))

def main():
    # Let's load the file and hook the problem functions to get around issues 3
    # and 4.
    b = angr.Project("simple_hash")
    b.hook(0x80487EC, mm)
    b.hook(0x8048680, moddi3)
    b.hook(0x80486E0, isalnum)

    # Here, we create a new symbolic state. To get around issue 5, we start
    # execution partway through `main()`.
    s = b.factory.blank_state(addr=0x8048A63)

    # To get around issue 1, we raise the solver timeout (specified in
    # milliseconds) to avoid situations where Z3 times out. Without this, with the
    # current way Z3 is used in angr, valid solutions end up being discarded
    # because Z3 can't find them fast enough.
    s.solver._solver.timeout=30000000

    # Since we started execution partway through main(), after the user input was
    # read, we need to manually set the user input.
    s.memory.store(0x080491A0, s.solver.BVS("ans", 999*8))

    # Now, we start the symbolic execution. We create a PathGroup and set up some
    # logging (so that we can see what's happening).
    sm = b.factory.simulation_manager(s, immutable=False)
    angr.manager.l.setLevel("DEBUG")

    # We want to explore to the "success" state (0x8048A94) while avoiding the
    # "failure" state (0x8048AF6). This takes a loong time (about an hour).
    sm.explore(find=0x8048A94, avoid=0x8048AF6)

    # We're done!
    return sm.found[0].solver.eval(sm.found[0].memory.load(0x080491A0, 100), cast_to=str).strip('\0\n')

def test():
    assert main() == 'EwgHWpyND'

if __name__ == '__main__':
    print main()
