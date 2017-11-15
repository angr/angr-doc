import logging
import logging
import struct
import sys

import angr


########################################
# helper functions for debugging
#######################################
def to_asmstring(state, addr, length):
    global p
    project = p
    try:
        conc = state.solver.eval
        addr =  conc(addr)
        code = "".join(project.loader.memory.read_bytes(addr,length))
        md = project.arch.capstone
        inst = "; ".join(["%s %s" %(i.mnemonic, i.op_str) for i in md.disasm(code,addr)])
        return "%x: %s" %(addr, inst.split(";")[0])
    except TypeError:
        # pypy seems to throw a TypeError in Capstone :(
        return ""


def debug_func(state):
    print to_asmstring(state, state.regs.eip, 10)

    addr = state.solver.eval(state.regs.eip)
    print hex(addr)

#######################################

#WIN_HASH = "D5C0E6E33E3C16853457C96C11C626F3628E95480000160ABFE0AA76C108E671".decode("hex")

#WIN_HASH = "BF3666668F5581A7EC65F192388BD64D4CC3B3610000275DAC894722C10986F6".decode("hex")

WIN_HASH = "C03922D0206DC3A33016010D6C66936E953ABAB9000010AE805CE8463CBE9A2D".decode("hex")

def get_hash_map(init_addr):
    """
		This function will return the winnig hash but in the expected shape to win. it means
        the expected hash must be like the following table.

	for instance:
		c0d5000000000000
		e3e6000000000000
		:
		:
	"""
    addr = init_addr
    hash_map = []
    for i in xrange(0, len(WIN_HASH), 2):
        pair = WIN_HASH[i:i+2]
        hash_map.append((addr, ord(pair[1])))
        hash_map.append((addr+1, ord(pair[0])))
        addr += 8

    return hash_map

#logging.getLogger('angr').setLevel(logging.DEBUG)
#logging.getLogger('angr.manager').setLevel(logging.DEBUG)

def hook_printf(state):
    pass

def hook_security_check_cookie(state):
    pass

def get_table(state):
	#this function will return the table of numbers used in the board
	base_addr_table = 0x41D450
	current_addr = base_addr_table
	end_addr = 0x0041E0D0

	t = []
	conc = state.solver.eval
	while current_addr < end_addr:
		n = conc(state.memory.load(current_addr, 8))
		pn = struct.unpack(">Q", struct.pack("<Q", n))[0]
		t.append(pn)
		current_addr += 8

	return t


###############################################
#step 0:
#   initializing state. In this step we crate the exe sym emulation
#   hook functions embedded in the binary (not OS call)
##############################################
load_options={}
p = angr.Project("sokohashv2.0.exe")

p.hook(0x0040103E, hook_printf,length=5)
p.hook(0x00401225, hook_printf,length=5)
p.hook(0x00401243, hook_printf,length=5)
p.hook(0x00401253, hook_security_check_cookie,length=5)

print "Initiating state"

#we are not starting from 401000 because it is not working properly.
#probably due to we are calling the function directly (it's mean creating an
#blank_state and setting addr manually
initial_state = p.factory.blank_state(addr=0x401003)
start = initial_state.regs.ebp
################################################


###############################################
#step 1:
#    this step is to identify what are we controling, and set restrictions for these, controlled, mem areas
#    In this case, the restrictions are asociated to values of the sokohash table.
#    (the parameters must be included in the sokohash universe numbers)
##############################################
print "Setting params restrictions (precontions)"
#first of all we will set the restrictions for out parameters in the initial
#state. to set that, we will load the addresses (this load will return a
#symbolic memory (another alternative can be use BVS and memory.store these bit
#vectors

r1 = initial_state.memory.load(start+0x08, 8, endness=p.arch.memory_endness)
r2 = initial_state.memory.load(start+0x10, 8, endness=p.arch.memory_endness)
r3 = initial_state.memory.load(start+0x18, 8, endness=p.arch.memory_endness)
r4 = initial_state.memory.load(start+0x20, 8, endness=p.arch.memory_endness)

list_cons_v1 = []
list_cons_v2 = []
list_cons_v3 = []
list_cons_v4 = []
for i in get_table(initial_state):
	list_cons_v1.append(r1==i)
	list_cons_v2.append(r2==i)
	list_cons_v3.append(r3==i)
	list_cons_v4.append(r4==i)

or_v1 = initial_state.solver.Or(*list_cons_v1)
or_v2 = initial_state.solver.Or(*list_cons_v2)
or_v3 = initial_state.solver.Or(*list_cons_v3)
or_v4 = initial_state.solver.Or(*list_cons_v4)


initial_state.add_constraints(initial_state.solver.And(or_v1,or_v2,or_v3,or_v4))
##############################################

#for debugging only
#initial_state.inspect.b('instruction', when=angr.BP_BEFORE, action=debug_func)

# Explore the paths until after the hash is computed
#path = p.factory.path(initial_state)

#FIND=0x00402CCB
#ex = p.surveyors.Explorer(start=path, find=FIND)
#ex.run()

#we will run until the end. We are using path_group becouse the angr-doc
#recommends use it instead of p.surveyors. (aparently, it is the feature)

#############################################
#step 2:
#	simbolic execute until the expected address is reach. This step will generate
#	the model to ask about values.

##############################################
FIND=0x40123E
#run sym execute
sm = p.factory.simulation_manager(initial_state, threads=8)
sm.explore(find=FIND)

#now we will get the supposed final state (the state after the symbolic execution)
found_s = sm.found[0]

conds=[]

conc = initial_state.solver.eval #this is used to concrete an symbolic value

for addr, value in get_hash_map(0x04216C0):
    memory = found_s.memory.load(addr, 1, endness=p.arch.memory_endness)
    print "Addr: %x --> %s" % (addr, hex(value))
    conds.append((memory == value))

found_s.add_constraints(found_s.solver.And(*conds))
##############################################



##############################################
#step 3:
#	This step is used to ask the model differents thinks. In this case
#	we will ask about the values in the init state (r1, r2, r3, r4), and the
#	model will returns the values expected to reath the model in found_s state

import binascii
solution1 = found_s.solver.eval(r1)
print "x: ", hex(solution1)

solution2 = found_s.solver.eval(r2)
print "y: ", hex(solution2)

solution3 = found_s.solver.eval(r3)
print "z:", hex(solution3)

solution4 = found_s.solver.eval(r4)
print "w:", hex(solution4)
##############################################

sys.stdout.flush()
