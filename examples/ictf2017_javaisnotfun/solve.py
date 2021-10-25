#!/usr/bin/env python


import angr
import os
from angr.procedures.java import JavaSimProcedure
from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor
from  angr.storage.file import Flags
import claripy
from claripy.backends.backend_smtlib_solvers import z3str_popen  # pylint:disable=unused-import


# This is a solution for the challenge javaisnotfun at ictf2017
# You can find a writeup here (in Chinese):
# https://ctftime.org/writeup/5964
# This code only solve 1 round of the "challenge-response" game inside the challenge.
# The equivalent python code to solve 1 round of the game is in the function: solve_given_numbers_python

# This is an example of:
# - How angr can solve programs written in a mix of Java and native code (communicating using the JNI interface)
# - How to solve a challenge-response problem


self_dir = os.path.dirname(os.path.realpath(__file__))


fake_output_fd = None
fake_input_fd = None


def solve_given_numbers_python(gnumbers):
    def scramble(c3,c4,c5):
        m  = [2,7,3,5,2,9,6,5,8,4]
        s1 = [3,8,1,3,9,1,2,4,2,2]
        sh = [1,4,3,2,2,2,3,1,4,1]
        s2 = [4,3,2,3,1,3,3,3,7,1]
        c3 = c3 * m[c4] + s1[c4]
        if(c5 < 5):
            c3 = (c3<<sh[c5]) + s2[c5]
        else:
            c3 = (c3>>sh[c5]) + s2[c5]
        return c3

    c1, c2, c3, c4, c5 = gnumbers
    s1 = c1+2
    s2 = c2*3 +1
    s3 = scramble(c3<<8,c4,c5)
    return s1,s2,s3


class Random_nextInt(JavaSimProcedure):
    __provides__ = (
        ("java.util.Random", "nextInt(int)"),
    )
    def run(self, _, length): # pylint: disable=W0221
        bvs = claripy.BVS("Random.nextInt", 32)
        cs =  claripy.And(claripy.SGE(bvs, 0), claripy.SLE(bvs, length))
        self.state.add_constraints(cs)
        return bvs


class Dummy_valueOf(JavaSimProcedure):
    __provides__ = (
        ("java.lang.Integer", "valueOf(int)"),
    )
    def run(self, intv): # pylint: disable=W0221
        return intv

# When the program prints to stdout, we constraint symbolic data written to stdout
# with whatever was printed by the concrete execution of the program
# (which we previously stored in /fake/output)
class Custom_Print(JavaSimProcedure):
    __provides__ = (
        ("NotFun", "print(java.lang.Object)"),
    )
    def run(self, _, obj): # pylint: disable=W0221
        def read_line_from_file(ff):
            #assuming that ff contains BV
            line = b""
            while True:
                vv = ff.read_data(1)[0]
                if vv.symbolic:
                    break
                ct = bytes(chr(vv.args[0]), 'utf-8')
                if ct == b"\n":
                    break
                line += ct
            return line

        # we don't care about printed fixed strings
        if isinstance(obj, angr.engines.soot.values.strref.SimSootValue_StringRef):
            return

        ff = self.state.posix.fd[fake_output_fd]
        value = int(read_line_from_file(ff))
        cs = (obj == claripy.BVV(value, 32))
        self.state.add_constraints(cs)


# When the program gets an Integer from stdin, we return one of the symbolic variables
# we previously stored in /fake/input
# (containing what the user has to insert to solve the game)
class Custom_getInt(JavaSimProcedure):
    __provides__ = (
        ("NotFun", "getInt()"),
    )
    def run(self, _): # pylint: disable=W0221
        return self.state.posix.fd[fake_input_fd].read_data(4)[0]


def solve_given_numbers_angr(numbers):
    global fake_input_fd, fake_output_fd


    binary_path = os.path.join(self_dir, "bin/service.jar")
    jni_options = {'jni_libs': ['libnotfun.so']}
    project = angr.Project(binary_path, main_opts=jni_options)
    # hooks
    project.hook(SootMethodDescriptor(class_name="java.util.Random", name="nextInt", params=('int',)).address(), Random_nextInt())
    project.hook(SootMethodDescriptor(class_name="java.lang.Integer", name="valueOf", params=('int',)).address(), Dummy_valueOf())
    project.hook(SootMethodDescriptor(class_name="NotFun", name="print", params=('java.lang.Object',)).address(), Custom_Print())
    project.hook(SootMethodDescriptor(class_name="NotFun", name="getInt", params=()).address(), Custom_getInt())

    # set entry point to the 'game' method
    game_method = [m for m in project.loader.main_object.classes['NotFun'].methods
                     if m.name == "game"][0]
    game_entry = SootMethodDescriptor.from_soot_method(game_method).address()
    entry = project.factory.blank_state(addr=game_entry)
    simgr = project.factory.simgr(entry)

    # Create a fake file with what it is going to be printed to the user (concrete)
    fake_output_fd = entry.posix.open(b"/fake/output", Flags.O_RDWR)
    ff = entry.posix.fd[fake_output_fd]
    tstr = b"".join([bytes(str(n), 'utf-8') + b"\n" for n in numbers])
    ff.write_data(tstr, len(tstr))
    ff.seek(0)

    # Create a fake file with what the user as to insert (symbolic)
    fake_input_fd = entry.posix.open(b"/fake/input", Flags.O_RDWR)
    ff = entry.posix.fd[fake_input_fd]
    solutions = [claripy.BVS("solution%d" % (i), 32) for i in range(3)]
    for s in solutions:
        ff.write_data(s, 4)
    ff.seek(0)

    print("="*10 + " SYMBOLIC EXECUTION STARTED")
    while(len(simgr.active)>0):
        simgr.step()
        print("===== " + str(simgr))
        print("===== " + ",".join([str(a.addr) for a in simgr.active if type(a.addr)==SootAddressDescriptor]))

        # If we reach block_idx 30, it means that we solved 1 round of the game --> we stash the state
        # If we reach the gameFail() method, it means that we failed --> we prune the state
        simgr.move('active', 'stashed', lambda a: type(a.addr) == SootAddressDescriptor
                   and a.addr.method == SootMethodDescriptor("NotFun", "game", ()) and a.addr.block_idx == 30)
        simgr.move('active', 'pruned', lambda a: type(a.addr) == SootAddressDescriptor
                   and a.addr.method == SootMethodDescriptor("NotFun", "gameFail", ()))

    print("="*10 + " SYMBOLIC EXECUTION ENDED")
    assert len(simgr.stashed) == 1
    win_state = simgr.stashed[0]
    numeric_solutions = []
    for s in solutions:
        es = win_state.solver.eval_atmost(s, 2)
        assert len(es) == 1
        numeric_solutions.append(es[0])
    return numeric_solutions


# You can create other challenge-response pairs by using the 'solve_given_numbers_python' function

def test_t1():
    assert solve_given_numbers_angr([60, 86, 203, 8, 6]) == [62, 259, 51971]


def test_t2():
    assert solve_given_numbers_angr([50, 87, 10, 7, 3]) == [52, 262, 51219]


def test():
    test_t1()
    test_t2()


if __name__ == "__main__":
    import logging
    logging.getLogger('cle.backends.soot').setLevel('DEBUG')
    logging.getLogger('cle.backends.apk').setLevel('DEBUG')
    logging.getLogger('cle.backends.jar').setLevel('DEBUG')
    logging.getLogger("angr").setLevel("INFO")
    logging.getLogger("angr.state_plugins").setLevel("INFO")
    logging.getLogger('angr.state_plugins.jni_references').setLevel("DEBUG")
    logging.getLogger('archinfo.arch_soot').setLevel("DEBUG")
    test()
