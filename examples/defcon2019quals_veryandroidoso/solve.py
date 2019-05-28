#!/usr/bin/env python

import angr
import os
from angr.procedures.java import JavaSimProcedure
from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor
import claripy


class getSecretNumber_sp(JavaSimProcedure):
    __provides__ = (
        ("ooo.defcon2019.quals.veryandroidoso.Solver", "getSecretNumber(int)"),
    )

    tstr = "105 71 127 221 12 24 237 85 2 143 81 214 5 79 100 82 44 225 80 5 2 177 133 113 244 238 241 218 214 83 169 112 233 154 245 14 26 167 104 50 208 241 229 70 12 3 219 15 88 34 197 185 97 205 147 95 218 159 70 129 255 145 43 49 17 197 210 68 69 210 74 59 249 41 182 11 99 106 146 250 113 183 183 193 202 81 227 242 44 1 199 153 120 48 78 65 230 173 71 15 103 89 61 109 172 7 97 101 58 126 169 97 105 80 198 188 240 219 29 14 41 139 157 117 107 98 191 222 136 247 45 93 4 154 113 108 192 154 5 76 66 134 244 227 132 238 150 201 86 237 124 152 134 199 152 117 168 43 61 129 222 245 111 109 155 142 16 101 72 191 231 213 224 26 149 87 171 79 174 23 108 245 195 70 253 36 207 226 39 13 210 175 223 178 93 16 96 209 52 247 230 58 198 1 40 75 203 45 234 156 214 244 141 89 132 229 29 156 190 108 88 10 28 105 180 182 157 23 234 17 249 18 210 62 31 236 97 190 1 236 17 102 33 84 5 131 149 198 122 86 126 90 235 175 58 176"

    def run(self, idx): # pylint: disable=W0221
        cidxlist = self.state.solver.eval_upto(idx, 256)
        if len(cidxlist) == 1:
            cidx = cidxlist[0]
            ii = int(self.tstr.split(" ")[cidx], 10)
            return claripy.BVV(ii, 32)
        else:
            bvs = claripy.BVS("gsn", 32)
            contraint_list = [claripy.And(bvs == int(self.tstr.split(" ")[cidx], 10), idx==cidx) for cidx in cidxlist]
            fc = claripy.Or(*contraint_list)
            print(repr(fc)[:200]+" ... "+repr(fc)[-200:])
            self.state.add_constraints(fc)
            return bvs


class scramble_sp(JavaSimProcedure):
    __provides__ = (
        ("ooo.defcon2019.quals.veryandroidoso.Solver", "scramble(int)"),
    )
    def run(self, ooo): # pylint: disable=W0221
        r = 2
        return ((ooo+r+321)%256)


def solve(apk_location):
    def is_success_state(state):
        if type(state.addr) == SootAddressDescriptor and state.addr.method == SootMethodDescriptor.from_soot_method(onclick_method):
            sols = state.solver.eval_upto(state.memory_soot.stack.load("$z0"), 2)
            assert(len(sols) == 1)
            if sols[0] == 1:
                return True
        return False

    def is_fail_state(state):
        if type(state.addr) == SootAddressDescriptor and state.addr.method == SootMethodDescriptor.from_soot_method(onclick_method):
            sols = state.solver.eval_upto(state.memory_soot.stack.load("$z0"), 2)
            assert(len(sols) == 1)
            if sols[0] == 0:
                return True
        return False


    sdk_path = os.path.join(os.path.expanduser("~"), "Android/Sdk/platforms/")
    if not os.path.exists(sdk_path):
        print("cannot run test_apk_loading since there is no Android SDK folder")
        return None

    loading_opts = {'android_sdk': sdk_path,
                    'entry_point': 'ooo.defcon2019.quals.veryandroidoso.MainActivity.onCreate',
                    'entry_point_params': ('android.os.Bundle', ),
                    'supported_jni_archs': ['x86']}
    # extern_size=0x800000 prevents CLE bug
    project = angr.Project(apk_location, main_opts=loading_opts, extern_size=0x800000)


    project.hook(SootMethodDescriptor(class_name="ooo.defcon2019.quals.veryandroidoso.Solver", name="getSecretNumber", params=('int',)).address(), getSecretNumber_sp())
    project.hook(SootMethodDescriptor(class_name="ooo.defcon2019.quals.veryandroidoso.Solver", name="scramble", params=('int',)).address(), scramble_sp())

    onclick_method = [m for m in project.loader.main_object.classes['ooo.defcon2019.quals.veryandroidoso.MainActivity$1'].methods if m.name == "onClick"][0]
    game_entry = SootMethodDescriptor.from_soot_method(onclick_method).address()
    game_entry.block_idx = 1
    game_entry.stmt_idx = 9

    entry = project.factory.blank_state(addr=game_entry)
    ns = 9
    solutions = [claripy.BVS("solution%d" % (i), 32) for i in range(ns)]
    for i, bvs in enumerate(solutions):
        entry.memory_soot.stack.store("$i"+str(i), bvs)
    for i in range(0,8+1):
        entry.add_constraints(claripy.And(solutions[i]>=0, solutions[i]<256))

    simgr = project.factory.simgr(entry)
    simgr.step()

    print("="*10 + " SYMBOLIC EXECUTION STARTED")
    tpruned = 0
    mactivepath = 0
    while(len(simgr.active)>0):
        simgr.step()
        print("===== " + str(simgr) + " --- " + str(tpruned + len(simgr.pruned)) + " " + str(mactivepath))
        print("===== " + ",".join([str(a.addr)[-15:] for a in simgr.active if type(a.addr)==SootAddressDescriptor]))

        simgr.move('active', 'stashed', is_success_state)
        simgr.move('active', 'pruned', is_fail_state)

        mactivepath = max(mactivepath, len(simgr.active))

        # uncommenting the following line will make the code finish sooner
        # if len(simgr.stashed)>0: break

        if(len(simgr.pruned) > 50):
            tpruned += len(simgr.pruned)
            simgr.drop(stash='pruned')

    print("="*10 + " SYMBOLIC EXECUTION ENDED")

    print(simgr)
    print("Max active paths: " + str(mactivepath))

    #import IPython; IPython.embed();

    assert(len(simgr.stashed) == 1)

    ss = simgr.stashed[0]
    intsols = []
    for sol in solutions:
        new_vals = ss.solver.eval_upto(sol,256)
        assert(len(new_vals) == 1)
        intsols.append(new_vals[0])

    solution = b"OOO{%s}" % b"".join([b"%02x"%i for i in intsols])
    return solution


if __name__ == "__main__":
    import logging
    logging.getLogger('cle.backends.soot').setLevel('DEBUG')
    logging.getLogger('cle.backends.apk').setLevel('DEBUG')
    logging.getLogger('cle.backends.jar').setLevel('DEBUG')
    logging.getLogger("angr").setLevel("INFO")
    logging.getLogger("angr.state_plugins").setLevel("ERROR")
    logging.getLogger('angr.state_plugins.jni_references').setLevel("INFO")
    logging.getLogger('angr.engines.engine').setLevel("WARNING")
    logging.getLogger('archinfo.arch_soot').setLevel("DEBUG")

    flag = solve("ooo.defcon2019.quals.veryandroidoso.apk")
    if flag is not None:
        print(b"FLAG: " + flag)
        assert flag == b"OOO{fab43416484944beba}"
