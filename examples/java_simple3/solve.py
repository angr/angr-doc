
import os
import angr
import logging

from claripy.backends.backend_smtlib_solvers import z3str_popen  # pylint:disable=unused-import

self_dir = os.path.dirname(os.path.realpath(__file__))


def test_java_simple3():
    binary_path = os.path.join(self_dir, "simple3.jar")
    project = angr.Project(binary_path, load_options={"auto_load_libs": False})
    entry = project.factory.entry_state()
    simgr = project.factory.simgr(entry)
    simgr.explore()

    state = simgr.deadended[0]
    # simple3.jar return the character after the inserted one
    # we constrain stdout to "c" and we expected stdin to be "b"
    state.add_constraints(state.posix.stdout.content[0][0] == state.solver.BVV(ord(b"c"), 8))
    assert state.posix.stdin.concretize() == [b"b"]


def test():
    test_java_simple3()


if __name__ == "__main__":
    logging.getLogger("angr.engines.soot.engine").setLevel("DEBUG")
    logging.getLogger("angr.factory").setLevel("DEBUG")
    test()
