#!/usr/bin/env python
import angr, simuvex

def main():
    b = angr.Project("very_success", load_options={"auto_load_libs":False})
    # create a state at the checking function
    # Since this is a windows binary we have to start after the windows library calls
    # remove lazy solves since we don't want to explore unsatisfiable paths
    s = b.factory.blank_state(addr=0x401084, remove_options={simuvex.o.LAZY_SOLVES})
    # set up the arguments on the stack
    s.mem[s.regs.esp+12:] = s.se.BVV(40, s.arch.bits)
    s.mem[s.regs.esp+8:].dword = 0x402159
    s.mem[s.regs.esp+4:].dword = 0x4010e4
    s.mem[s.regs.esp:].dword = 0x401064
    # store a symbolic string for the input
    s.mem[0x402159:] = s.se.BVS("ans", 8*40)
    # explore for success state, avoiding failure
    pg = b.factory.path_group(s, immutable=False)
    pg.explore(find=0x40106b, avoid=0x401072)
    # print the string
    found_state = pg.found[0].state
    return found_state.se.any_str(found_state.memory.load(0x402159, 40)).strip('\0')

def test():
    assert main() == 'a_Little_b1t_harder_plez@flare-on.com'

if __name__ == '__main__':
    print main()
