
import logging

#l = logging.getLogger('angr.manager').setLevel(logging.DEBUG)

import angr

def solve(s):
    p = angr.Project("sorcery_dist/%s" % s,
            auto_load_libs=False
            )
    cfg = p.analyses.CFG(show_progressbar=True)

    func = cfg.functions[0x4030fc]
    # dump all cmp cls
    s = ""
    for block in sorted(func.blocks, key=lambda b: b.addr):
        insns = [ insn for insn in block.capstone.insns if insn.mnemonic == 'cmp' and insn.operands[0].type == 1 and insn.operands[0].reg in (2, 10) ]
        if not insns:
            continue
        insn = insns[0]
        imm = insn.operands[1].imm
        s += chr(imm)
    return s


def main():
    import pwn
    host, port = "cm2k-sorcery_13de8e6bf26e435fc43efaf46b488eae.quals.shallweplayaga.me", 12002
    r = pwn.remote(host, port)
    print r.readuntil("newline\n")
    while True:
        filename = r.readuntil("\n").strip("\n")
        print filename
        sol = solve(filename)
        print repr(sol)
        data = sol.encode("base64")
        print "Send this:" + data
        r.send(data)


if __name__ == "__main__":
    main()

# The flag is: don't forget me when you're famous Klousovnec
