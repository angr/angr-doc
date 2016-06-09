## Full writeup on flag 2 found on http://www.ctfhacker.com
## Binary found here: http://csapp.cs.cmu.edu/3e/bomb.tar

import angr, logging


def solve_flag_1():
    
    # shutdown some warning produced by this example
    logging.getLogger('simuvex.vex.irsb').setLevel(logging.ERROR)

    proj = angr.Project('bomb', load_options={'auto_load_libs':False})

    start = 0x400ee0
    bomb_explode = 0x40143a
    end = 0x400ef7

    # initial state is at the beginning of phase_one()
    state = proj.factory.blank_state(addr=start)

    # a symbolic input string with a length up to 128 bytes
    arg = state.se.BVS("input_string", 8 * 128)

    # read_line() reads a line from stdin and stores it a this address
    bind_addr = 0x603780

    # bind the symbolic string at this address
    state.memory.store(bind_addr, arg)

    # phase_one reads the string [rdi]
    state.add_constraints(state.regs.rdi == bind_addr)

    # Attempt to find a path to the end of the phase_1 function while avoiding the bomb_explode
    path = proj.factory.path(state=state)

    ex = proj.surveyors.Explorer(start=path, find=(end,),
                                 avoid=(bomb_explode,),
                                 enable_veritesting=True)
    ex.run()
    if ex.found:

        found = ex.found[0].state
        return found.se.any_str(arg).rstrip(chr(0)) # remove ending \0

    pass

def solve_flag_2():

    proj = angr.Project('bomb', load_options={'auto_load_libs':False})
    bomb_explode = 0x40143a

    # Start analysis at the phase_2 function after the sscanf
    state = proj.factory.blank_state(addr=0x400f0a)

    # Sscanf is looking for '%d %d %d %d %d %d' which ends up dropping 6 ints onto the stack
    # We will create 6 symbolic values onto the stack to mimic this 
    for i in xrange(6):
        state.stack_push(state.se.BVS('int{}'.format(i), 4*8))

    # Attempt to find a path to the end of the phase_2 function while avoiding the bomb_explode
    path = proj.factory.path(state=state)
    ex = proj.surveyors.Explorer(start=path, find=(0x400f3c,),
                                 avoid=(bomb_explode,),
                                 enable_veritesting=True)
    ex.run()
    if ex.found:
        found = ex.found[0].state

        answer = []

        for x in xrange(3):
            curr_int = found.se.any_int(found.stack_pop())

            # We are popping off 8 bytes at a time
            # 0x0000000200000001
            # This is just one way to extract the individual numbers from this popped value
            answer.append(str(curr_int & 0xffffffff))
            answer.append(str(curr_int>>32 & 0xffffffff))

        return ' '.join(answer)

    pass


def solve_flag_3():

    args = []

    proj = angr.Project('bomb', load_options={'auto_load_libs':False})

    start = 0x400f6a # phase_3 after scanf()
    bomb_explode = 0x40143a
    end = 0x400fc9 # phase_3 before ret

    state = proj.factory.blank_state(addr=start)

    # we want to enumerate all solutions... let's have a queue
    queue = [state, ]
    while len(queue) > 0:

        state = queue.pop()
        #print "\nStarting symbolic execution..." 

        path = proj.factory.path(state=state)
        ex = proj.surveyors.Explorer(start=path, find=(end,),
                                     avoid=(bomb_explode,),
                                     enable_veritesting=True)
        ex.run()

        #print "Inserting in queue " + str(len(ex.active)) + " paths (not yet finished)"
        for p in ex.active:
            queue.append(p.state)

        #print "Found states are " + str(len(ex.found))
        #print "Enumerating up to 10 solutions for each found state"

        if ex.found:

            for p in ex.found:

                found = p.state
                found.stack_pop() # ignore, our args start at offset 0x8

                iter_sol = found.se.any_n_int(found.stack_pop(), 10) # ask for up to 10 solutions if possible
                for sol in iter_sol:

                    if sol == None:
                        break

                    a = sol & 0xffffffff
                    b = (sol >> 32) & 0xffffffff

                    #print "Solution: " + str(a) + " " + str(b)
                    args.append(str(a) + " " + str(b))

    return args           

def main():
    print "Flag    1: " + solve_flag_1()
    print "Flag    2: " + solve_flag_2()
    print "Flag(s) 3: " + str(solve_flag_3())
    

def test():
    assert solve_flag_1() == 'Border relations with Canada have never been better.'
    assert solve_flag_2() == '1 2 4 8 16 32'
    
    args_3 = ["0 207", "1 311", "2 707", "3 256", "4 389", "5 206", "6 682", "7 327"]
    res_3 = solve_flag_3()
    assert len(res_3) == len(args_3)
    for s in args_3:
        assert s in res_3


if __name__ == '__main__':
    
    # logging.basicConfig()
    # logging.getLogger('angr.surveyors.explorer').setLevel(logging.DEBUG)

    main()