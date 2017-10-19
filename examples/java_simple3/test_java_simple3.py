
import os

from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor
import angr
import logging


self_dir = os.path.dirname(os.path.realpath(__file__))

def test_java_simple3():
    binary_path = os.path.join(self_dir, "simple3.jar")

    proj = angr.Project(binary_path)
    print proj.loader.main_object._classes['simple3.Class1']

    simgr = proj.factory.simgr()
    main_method = next(proj.loader.main_object.main_methods)
    simgr.active[0].ip = SootAddressDescriptor(SootMethodDescriptor.from_method(main_method), 0, 0)

    simgr.explore()

    pp = simgr.deadended[0]
    pp.state.posix.set_pos(0, 0)
    pp.state.posix.set_pos(1, 0)
    ii = pp.state.posix.read_from(0, 1)
    oo = pp.state.posix.read_from(1, 1)
    pp.state.add_constraints(oo == pp.state.se.BVV(ord('c'), 8))

    print ii, "-->", oo
    cinput = chr(pp.state.se.eval(ii))
    print repr(cinput)
    assert cinput == "b"
   
    # import IPython; IPython.embed();

def main():
    test_java_simple3()

if __name__ == "__main__":
    logging.getLogger("angr.engines.soot.engine").setLevel("DEBUG")
    logging.getLogger("angr.factory").setLevel("DEBUG")
    main()
