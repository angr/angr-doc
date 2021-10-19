
import os
import angr
import logging

from claripy.backends.backend_smtlib_solvers import z3str_popen  # pylint:disable=unused-import

self_dir = os.path.dirname(os.path.realpath(__file__))


def test_java_simple4():
    binary_path = os.path.join(self_dir, "simple4.jar")
    project = angr.Project(binary_path, auto_load_libs=False)
    entry = project.factory.entry_state()
    simgr = project.factory.simgr(entry)
    simgr.explore()

    states = simgr.deadended
    assert len(states) == 2

    # the winning state has "W" on stdout and "F" on stdin
    winnning_states = [s for s in states if s.posix.stdout.concretize() == [b"W"]]
    assert len(winnning_states) == 1
    winning_state = winnning_states[0]
    flag = b"".join(winning_state.posix.stdin.concretize())
    assert flag == b"F"


def test():
    test_java_simple4()


if __name__ == "__main__":
    logging.getLogger("angr.engines.soot.engine").setLevel("DEBUG")
    logging.getLogger("angr.factory").setLevel("DEBUG")
    test()
