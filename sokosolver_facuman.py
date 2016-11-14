import angr
import sys
import simuvex
import struct
from itertools import combinations, product

#WIN_HASH = "C03922D0206DC3A33016010D6C66936E953ABAB9000010AE805CE8463CBE9A2D".decode("hex")
WIN_HASH = "D5C0E6E33E3C16853457C96C11C626F3628E95480000160ABFE0AA76C108E671".decode("hex")



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


def get_table(state):
    base_addr_table = 0x41D450
    current_addr = base_addr_table
    end_addr = 0x0041E0D0

    t = []
    conc = state.se.any_int
    while current_addr < end_addr:
        n = conc(state.memory.load(current_addr, 8))
        pn = struct.unpack(">Q", struct.pack("<Q", n))[0]
        t.append(pn)
        current_addr += 8

    return t

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
    to_find = 0x0040123E
    hash_addr = 0x04216C0

    proj.hook(0x0040102c, do_nothing,length=6)
    proj.hook(0x00401033, do_nothing,length=6)
    proj.hook(0x0401028, do_repmovsd, length=2)
    proj.hook(0x0401253, do_nothing, length=5) 
    proj.hook(0x040103E, do_nothing, length=5) 
    proj.hook(0x0401225, do_nothing, length=5) 
    proj.hook(0x0401243, do_nothing, length=5) 

    # initial state
    init = proj.factory.blank_state(addr=0x401013)
    
    init.regs.ebp = init.regs.esp + 0x78


    start = init.regs.ebp
    r1 = init.memory.load(start+0x08, 8, endness=proj.arch.memory_endness)
    r2 = init.memory.load(start+0x10, 8, endness=proj.arch.memory_endness)
    r3 = init.memory.load(start+0x18, 8, endness=proj.arch.memory_endness)
    r4 = init.memory.load(start+0x20, 8, endness=proj.arch.memory_endness)
    
    # search only for possible coords
    list_conds = []
    for p in get_table(init):
        list_conds.append(p == r1)
        list_conds.append(p == r2)
        list_conds.append(p == r3)
        list_conds.append(p == r4)

    init.add_constraints(init.se.Or(*list_conds))



    buffer = init.memory.load(init.regs.ebp + 0x8, 0x20)
        
    pg = proj.factory.path_group(init, threads=8, save_unconstrained=True)
    pg.explore(find=to_find)

    path = pg.found[0]

    found = path.state

    # Resulting hash must be winning hash
    # Print expected hash and resulting hash for verification
    conds=[]
    conc = init.se.any_int
    for addr, value in get_hash_map(0x04216C0):
        memory = found.memory.load(addr, 1)
        print "Addr: %x --> %s" % (addr, hex(value))
        conds.append((memory == value))

    found.add_constraints(init.se.And(*conds))

    import binascii
    r = binascii.hexlify(found.se.any_str(buffer))
    print r[0:16]
    print r[16:32]
    print r[32:48]
    print r[48:64]



if __name__ == '__main__':
    #angr.path_group.l.setLevel('DEBUG')
    main()


