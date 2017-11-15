import angr
import sys
import struct
from itertools import combinations, product

WIN_HASH = "C03922D0206DC3A33016010D6C66936E953ABAB9000010AE805CE8463CBE9A2D".decode("hex")


def get_valid_coords():
    var = """#                            #
#            O               #
#         x                  #
#                   w        #
#           *                #
# ##    ####   ######   ###  #
##  #  ##  ##  ##  ##  ##    #
##     ##  ##  ##  ##  ##    #
##     ##  ##  #####   ####  #
##     ##  ##  ## ##   ##    #
##  #  ##  ##  ##  ##  ##    #
# ##    ####   ##  ##   ###  #
#                            #
#                            #
#                      yz    #
#                     O      #
/                            #
#                            #
"""

    valid = []
    invalid = (list(product(range(7,12),[9,10])) +
               list(product([7,8],[17,18])) )

    x = 1
    for line in var.splitlines():
        line = line.strip()
        line = line[1:len(line)-1]
        y = 1
        for i in line:
            if i not in ["O", "#", "/"]:
                if (x,y) not in invalid:
                    valid.append((x,y))
            y += 1
        x += 1

    return valid

def do_memset(state):
    addr = 0x417490
    with open("matrix.bin","rb") as f:
        content = f.read()
        for i in content:
            state.memory.store(addr, state.solver.BVV(ord(i), 8 * 1))
            addr += 1

    start_off = 0x41d450 - addr
    end_off = 0x41e0c8 - addr
    coords = []
    for i in xrange(start_off, end_off+8, 8):
        coords.append(struct.unpack("<Q", content[i:i+8])[0])

    return coords

def do_repmovsd(state):
    # angr does not like rep movsd
    # we do it by hand
    buffer = state.memory.load(state.regs.esi, 8 * 4)
    state.memory.store(state.regs.edi, buffer)

def do_nothing(state):
    pass

def get_hash_map(init_addr):
    addr = init_addr
    hash_map = []
    for i in xrange(0, len(WIN_HASH), 2):
        pair = WIN_HASH[i:i+2]
        hash_map.append((addr, ord(pair[1])))
        hash_map.append((addr+1, ord(pair[0])))
        addr += 8

    return hash_map


def main():
    proj = angr.Project('sokohashv2.0.exe', use_sim_procedures=True, load_options={"auto_load_libs": False})

    # addrs
    main = 0x401013
    to_find = 0x0040123E
    hash_addr = 0x04216C0

    # hooks
    func_hooks = [0x0040102C, 0x0401033]
    for addr in func_hooks:
        proj.hook(addr, do_nothing, length=6)

    func_hooks = [0x401215, 0x40121E, 0x401239, 0x40123C]
    for addr in func_hooks:
        proj.hook(addr, do_nothing, length=2)

    proj.hook(0x0401028, do_repmovsd, length=2)
    proj.hook(0x0401253, do_nothing, length=5)
    proj.hook(0x040103E, do_nothing, length=5)
    proj.hook(0x0401225, do_nothing, length=5)
    proj.hook(0x0401243, do_nothing, length=5)

    # initial state
    init = proj.factory.blank_state(addr=main)

    coords = do_memset(init)
    coord_dict = {}
    count = 0
    for i in get_valid_coords():
        #print "%s = %.16x" % (i, pos[count])
        coord_dict[coords[count]] = i
        count += 1

    init.regs.ebp = init.regs.esp + 0x78

    # search only for possible coords
    variables = []
    for i in xrange(0, 4):
        var = init.memory.load(init.regs.ebp + 0x8 + (0x8*i), 0x8, endness=proj.arch.memory_endness)
        variables.append(var)
        conds = []
        for p in coords:
            conds.append(p == var)
        init.add_constraints(init.solver.Or(*conds))

    # each coordinate must be distinct
    for v1,v2 in combinations(variables, 2):
        init.add_constraints(v1 != v2)

    buffer = init.memory.load(init.regs.ebp + 0x8, 0x20)

    sm = proj.factory.simulation_manager(init, threads=8, save_unconstrained=True)
    sm.explore(find=to_find)

    found = sm.found[0]

    # Resulting hash must be winning hash
    # Print expected hash and resulting hash for verification
    conds = []
    expected = []
    hash_map = get_hash_map(hash_addr)
    for addr, value in hash_map:
        memory = found.memory.load(addr, 1, endness=proj.arch.memory_endness)
        conds.append((memory == value))
        expected.append((hex(addr), hex(value)))
    print "Expected is '%s'\n\n" % expected

    found.add_constraints(init.solver.And(*conds))

    result = []
    hash_map = get_hash_map(hash_addr)
    for addr, value in hash_map:
        buf_ptr = found.memory.load(addr, 1)
        possible = found.solver.eval(buf_ptr)
        result.append((hex(addr), "0x%x" % possible))
    print "Result is '%s'\n\n" % result


    # Print solutions
    possible = found.solver.eval_upto(buffer, 1)
    for i, f in enumerate(possible):
        out = "%x" % f
        if len(out) < (0x20*2):
            continue

        names = ["x","y","z","w"]
        values = []
        for j in xrange(0, len(out), 16):
            value = out[j:j+16]
            unpk_value = struct.unpack("<Q", value.decode("hex"))[0]

            values.append((names[j//16], coord_dict[unpk_value]))
        print "\tSolution %d: %s" % (i, values)


if __name__ == '__main__':
    #angr.manager.l.setLevel('DEBUG')
    main()
    sys.stdout.flush()
