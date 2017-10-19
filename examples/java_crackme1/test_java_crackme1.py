
import os

from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor
import angr
import logging
import subprocess


self_dir = os.path.dirname(os.path.realpath(__file__))

def test_java_crackme1():
    binary_path = os.path.join(self_dir, "crackme1.jar")

    proj = angr.Project(binary_path)
    print proj.loader.main_object._classes['crackme1.Class1']

    simgr = proj.factory.simgr()
    main_method = next(proj.loader.main_object.main_methods)
    simgr.active[0].ip = SootAddressDescriptor(SootMethodDescriptor.from_method(main_method), 0, 0)
    simgr.explore()

    terminated_paths = simgr.deadended
    assert len(terminated_paths) > 1

    winnning_paths = []
    for pp in terminated_paths:
        pp.state.posix.set_pos(0, 0)
        pp.state.posix.set_pos(1, 0)
        oo = pp.state.posix.read_from(1, 1)
        # a winning path is printing 'W'
        pp.state.add_constraints(oo == pp.state.se.BVV(ord('W'), 8))
        if pp.satisfiable():
            winnning_paths.append(pp)
    assert len(winnning_paths) == 1
    winning_path = winnning_paths[0]

    # on the winning path, we ask for the input
    ii = winning_path.state.posix.read_from(0, 10)
    print ii
    print winning_path.state.se.constraints

    flags = winning_path.state.se.eval_upto(ii, 2, cast_to=str)
    # only 1 possible solution
    print repr(flags)
    assert len(flags) == 1
    flag = flags[0]
    print repr(flag)
    assert flag == "JaV$!sB4D!"

    # verify against the real code
    p = subprocess.Popen(["java", "-jar", "crackme1.jar"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    res, _ = p.communicate(flag)
    print repr(res)
    assert res == "W"


def main():
    test_java_crackme1()


if __name__ == "__main__":
    logging.getLogger("angr.engines.soot.engine").setLevel("DEBUG")
    logging.getLogger("angr.factory").setLevel("DEBUG")
    main()
