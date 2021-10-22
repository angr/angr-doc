
import os
import angr
import logging
import subprocess

from claripy.backends.backend_smtlib_solvers import z3str_popen  # pylint:disable=unused-import

self_dir = os.path.dirname(os.path.realpath(__file__))

def test_java_crackme1():
    binary_path = os.path.join(self_dir, "crackme1.jar")
    project = angr.Project(binary_path, auto_load_libs=False)
    entry = project.factory.entry_state()
    simgr = project.factory.simgr(entry)
    simgr.explore()

    terminated_states = simgr.deadended
    assert len(terminated_states) > 1

    # the winning state has "W" on stdout and "JaV$!sB4D!" on stdin
    winnning_states = [s for s in terminated_states if s.posix.stdout.concretize() == [b"W"]]
    assert len(winnning_states) == 1
    winning_state = winnning_states[0]
    flag = b"".join(winning_state.posix.stdin.concretize())
    assert flag == b"JaV$!sB4D!"

    # verify against the real code
    p = subprocess.Popen(["java", "-jar", binary_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    res, _ = p.communicate(flag)
    assert res == b"W"


def test():
    test_java_crackme1()


if __name__ == "__main__":
    logging.getLogger("angr.engines.soot.engine").setLevel("DEBUG")
    logging.getLogger("angr.factory").setLevel("DEBUG")
    test()
