## Full writeup on flag 2 found on http://www.ctfhacker.com     
## Binary found here: http://csapp.cs.cmu.edu/3e/bomb.tar
import sys
import angr
import logging
import claripy
from struct import unpack

class readline_hook(angr.SimProcedure):
    def run(self):
        pass

class strtol_hook(angr.SimProcedure):
    def run(self, str, end, base):
        return self.state.se.BVS("flag", 64, explicit_name=True)

def solve_flag_1():

    # shutdown some warning produced by this example
    logging.getLogger('angr.engines.vex.irsb').setLevel(logging.ERROR)

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
    ex = proj.surveyors.Explorer(start=state, find=(end,),
                                 avoid=(bomb_explode,),
                                 enable_veritesting=True)
    ex.run()

    if ex.found:
        found = ex.found[0]
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
    ex = proj.surveyors.Explorer(start=state, find=(0x400f3c,),
                                 avoid=(bomb_explode,),
                                 enable_veritesting=True)
    ex.run()

    if ex.found:
        found = ex.found[0]

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

        ex = proj.surveyors.Explorer(start=state, find=(end,),
                                     avoid=(bomb_explode,),
                                     enable_veritesting=True,
                                     max_active=8)
        ex.run()

        #print "Inserting in queue " + str(len(ex.active)) + " paths (not yet finished)"
        for p in ex.active:
            queue.append(p)

        #print "Found states are " + str(len(ex.found))
        #print "Enumerating up to 10 solutions for each found state"

        if ex.found:
            for p in ex.found:
                found = p
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


def solve_flag_4():

    avoid = 0x40143A
    find = 0x401061
    proj = angr.Project("./bomb", load_options={'auto_load_libs': False})

    state = proj.factory.blank_state(
        # let's get the address via its symbol
        # after a proj.analysis.CFG it can be recovered by
        # addr=proj.kb.functions.get('phase_4').addr,
        # we will just use the obj's symbol directly
        addr=proj.kb.obj.get_symbol('phase_4').addr,
        remove_options={angr.options.LAZY_SOLVES})
    sm = proj.factory.simgr(state)
    sm.explore(find=find, avoid=avoid)

    found = sm.found[0]

    # stopped on the ret account for the stack
    # that has already been moved

    answer = unpack('II', found.se.any_str(
        found.memory.load(found.regs.rsp - 0x18 + 0x8, 8)))

    return ' '.join(map(str, answer))


def solve_flag_5():

    def is_alnum(state, c):
        # set some constraints on the char, let it
        # be a null char or alphanumeric
        is_num = state.se.And(c >= ord("0"), c <= ord("9"))
        is_alpha_lower = state.se.And(c >= ord("a"), c <= ord("z"))
        is_alpha_upper = state.se.And(c >= ord("A"), c <= ord("Z"))
        is_zero = (c == ord('\x00'))
        isalphanum = state.se.Or(
            is_num, is_alpha_lower, is_alpha_upper, is_zero)
        return isalphanum

    # getting more lazy, let angr find the functions, and build the CFG
    proj = angr.Project("./bomb", load_options={'auto_load_libs': False})

    proj.analyses.CFG()

    start = proj.kb.obj.get_symbol('phase_5').addr
    avoid = proj.kb.obj.get_symbol('explode_bomb').addr
    # let's stop at the end of the function
    find = proj.kb.functions.get('phase_5').ret_sites[0].addr

    state = proj.factory.blank_state(
        addr=start, remove_options={angr.options.LAZY_SOLVES})
    # retrofit the input string on the stack
    state.regs.rdi = state.regs.rsp - 0x1000
    string_addr = state.regs.rdi
    sm = proj.factory.simgr(state)
    sm.explore(find=find, avoid=avoid)
    found = sm.found[0]

    mem = found.memory.load(string_addr, 32)
    for i in xrange(32):
        found.add_constraints(is_alnum(found, mem.get_byte(i)))
    return found.se.any_str(mem).split('\x00')[0]
    # more than one solution could, for example, be returned like this:
    # return map(lambda s: s.split('\x00')[0], found.se.any_n_str(mem, 10))


class read_6_ints(angr.SimProcedure):
    answer_ints = []  # class variable
    int_addrs = []

    def run(self, s1_addr, int_addr):
        self.int_addrs.append(int_addr)
        for i in range(6):
            bvs = self.state.se.BVS("phase6_int_%d" % i, 32)
            self.answer_ints.append(bvs)
            self.state.mem[int_addr].int.array(6)[i] = bvs

        return 6

def solve_flag_6():
    start = 0x4010f4
    read_num = 0x40145c
    find = 0x4011f7
    avoid = 0x40143A
    p = angr.Project("./bomb", load_options={'auto_load_libs': False})
    p.hook(read_num, read_6_ints)
    state = p.factory.blank_state(addr=start, remove_options={angr.options.LAZY_SOLVES})
    sm = p.factory.simgr(state)
    sm.explore(find=find, avoid=avoid)
    found = sm.found[0]

    answer = [found.se.any_int(x) for x in read_6_ints.answer_ints]
    return ' '.join(map(str, answer))

def solve_secret():
    start = 0x401242
    find = 0x401282
    avoid = (0x40127d, 0x401267,)
    readline = 0x40149e
    strtol = 0x400bd0

    p = angr.Project("./bomb", load_options={'auto_load_libs':False})
    p.hook(readline, readline_hook)
    p.hook(strtol, strtol_hook)
    state = p.factory.blank_state(addr=start, remove_options={angr.options.LAZY_SOLVES})
    flag = claripy.BVS("flag", 64, explicit_name=True)
    state.add_constraints(flag -1 <= 0x3e8)
    sm = p.factory.simgr(state)
    sm.explore(find=find, avoid=avoid)
    ### flag found
    found = sm.found[0]
    flag = found.se.BVS("flag", 64, explicit_name="True")
    return str(found.se.any_int(flag))

def main():
#   print "Flag    1: " + solve_flag_1()
    print "Flag    2: " + solve_flag_2()
    print "Flag(s) 3: " + str(solve_flag_3())
    print "Flag    4: " + solve_flag_4()
    print "Flag    5: " + solve_flag_5()
    print "Flag    6: " + solve_flag_6()
    print "Secret   : " + solve_secret()

def test():
#   assert solve_flag_1() == 'Border relations with Canada have never been better.'
#   print "Stage 1 ok!"

    assert solve_flag_2() == '1 2 4 8 16 32'
    print "Stage 2 ok!"

    args_3 = ["0 207", "1 311", "2 707", "3 256", "4 389", "5 206", "6 682", "7 327"]
    res_3 = solve_flag_3()
    assert len(res_3) == len(args_3)
    for s in args_3:
        assert s in res_3
    print "Stage 3 ok!"

    assert solve_flag_4() == '7 0'
    print "Stage 4 ok!"

    assert solve_flag_5().lower() == 'ionefg'
    print "Stage 5 ok!"

    assert solve_flag_6() == '4 3 2 1 6 5'
    print "Stage 6 ok!"

    assert solve_secret() == '22'
    print "Secret stage ok!"

if __name__ == '__main__':

    # logging.basicConfig()
    # logging.getLogger('angr.surveyors.explorer').setLevel(logging.DEBUG)

    main()
