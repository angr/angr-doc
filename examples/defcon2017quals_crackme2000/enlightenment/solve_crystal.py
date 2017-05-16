import angr
import sys
import os
import capstone

def solve(filename):
    p = angr.Project("acdde83f055b5bf9211d9ca1cbafbce2/%s" % filename, load_options={"auto_load_libs": False})

    cfg = p.analyses.CFGFast(force_complete_scan=False, show_progressbar=False)

    our_fn = sorted(p.kb.functions.values(), key=lambda x: x.size)[-2]

    not_crap = []
    for b in our_fn.blocks:
        t = b.capstone
        if len(t.insns) < 3:
            continue

        if t.insns[-3].insn.mnemonic == u"movzx" and \
                t.insns[-2].insn.mnemonic == u"cmp" and \
                (t.insns[-1].insn.mnemonic == u"jne" or \
                 t.insns[-1].insn.mnemonic == u"je"
                 ):
            not_crap.append(t)

    good = []
    for t in not_crap:
        if t.insns[-3].insn.operands[1].mem.base in \
                (capstone.x86_const.X86_REG_RAX, capstone.x86_const.X86_REG_ECX):
            good.append(t)

    really_good = sorted(good, key=lambda x: x.insns[-3].insn.operands[1].mem.disp)

    # print map(str, really_good)

    solution = ''.join(chr(k.insns[-2].insn.operands[1].imm) for k in really_good)

    return solution

def main():
    for i, filename in enumerate(os.listdir("acdde83f055b5bf9211d9ca1cbafbce2")):
        if i % 8 != int(sys.argv[1]):
            continue
        if "." in filename:
            continue
        print i, filename, '"%s"' % solve(filename)

if __name__ == "__main__":
    main()
