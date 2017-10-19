
import os

from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor
import angr
import logging


self_dir = os.path.dirname(os.path.realpath(__file__))

def test_java_simple4():
    binary_path = os.path.join(self_dir, "simple4.jar")

    proj = angr.Project(binary_path)
    print proj.loader.main_object._classes['simple4.Class1']

    simgr = proj.factory.simgr()
    main_method = next(proj.loader.main_object.main_methods)
    simgr.active[0].ip = SootAddressDescriptor(SootMethodDescriptor.from_method(main_method), 0, 0)

    simgr.explore()

    paths = simgr.deadended
    assert len(paths) == 2

    winnning_paths = []
    for pp in paths:
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
    ii = winning_path.state.posix.read_from(0, 1)
    solution = chr(winning_path.state.se.eval(ii))
    print repr(solution)
    assert solution == 'F'


def main():
    test_java_simple4()

if __name__ == "__main__":
    logging.getLogger("angr.engines.soot.engine").setLevel("DEBUG")
    logging.getLogger("angr.factory").setLevel("DEBUG")
    main()
