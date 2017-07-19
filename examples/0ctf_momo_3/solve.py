#!/usr/bin/env python

# This is a movfuscated binary from 0ctf 2016, debugging we can see
# that every byte from the flag gets moved this way:
# .text:0804ABAC                 mov     edx, dword_81FE260[edx*4]
# after, varying a few times the input and looking for differences
# with Qira we can see that it is expected for the content of
# 0x81fe6e0 and 0x81fe6e4 to be the same
# since the way the movfuscator "vm" access memory is always the same
# we can search for the same instructions (in the same order) to
# establish the targets for angr execution

import sys
import string
import angr
from angr.block import CapstoneInsn, CapstoneBlock


ins_char = 0x81fe6e0
flag_char = 0x81fe6e4

after_fgets = 0x08049653
mov_congrats = 0x0805356E


def main():
    p = angr.Project('./momo', load_options={'auto_load_libs': False})

    addr = after_fgets
    size = mov_congrats - after_fgets

    # let's disasm with capstone to search targets
    insn_bytes = ''.join(
        p.loader.memory.read_bytes(addr, size))

    insns = []
    for cs_insn in p.arch.capstone.disasm(insn_bytes, addr):
        insns.append(CapstoneInsn(cs_insn))
    block = CapstoneBlock(addr, insns, 0, p.arch)

    targets = []

    # let's keep track of the state
    state = 0
    for ins in block.insns:
        if state == 0:
            if ins.op_str == 'edx, dword ptr [edx*4 + 0x81fe260]':
                state += 1
                continue
        if state == 1:
            if ins.op_str == 'al, byte ptr [0x81fe6e0]':
                state += 1
                continue
        if state == 2:
            if ins.op_str == 'dl, byte ptr [0x81fe6e4]':
                targets.append(ins.address + ins.size)
                state = 0

    print "found {:d} targets".format(len(targets))
    assert len(targets) == 28

    flag_arr = ['0', 'c', 't', 'f', '{']

    for target in targets[5:]:
        print "\nexamining target {:#x}:".format(target)
        for trychar in string.printable:
            print trychar,
            sys.stdout.flush()
            flag = ''.join(flag_arr)+trychar
            state = p.factory.entry_state()
            state.posix.files[0].content.store(0, flag + "\n")

            e = p.surveyors.Explorer(start=state, find=(target,))
            e.run()

            assert len(e.found) == 1
            np = e.found[0]

            while(True):
                nb_size = target - np.addr
                if nb_size <= 0:
                    break
                np = p.factory.successors(np, size=nb_size).flat_successors[0]
            assert nb_size == 0

            al = np.regs.eax[7:0]
            dl = np.regs.edx[7:0]
            al_val = al._model_concrete.value
            dl_val = dl._model_concrete.value

            if al_val == dl_val:
                flag_arr.append(trychar)
                break

    return ''.join(flag_arr)


def test():
    assert main() == '0ctf{m0V_I5_tUr1N9_c0P1Et3!}'

if __name__ == '__main__':
    print main()
