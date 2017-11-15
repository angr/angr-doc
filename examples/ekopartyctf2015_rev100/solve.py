
# This challenge is super big, and it's impossible to solve with IDA alone.
# However, we are sure that most of the code is just garbage - you can't have 
# a 100-point challenge with that much non-garbage code. Therefore the idea is 
# to use GDB along with hardware breakpoints to find out where each byte is 
# verified, and then run that single part of code inside angr to solve the 
# password.

from angr.procedures.stubs.UserHook import UserHook
import angr

def prepare_state(state, known_passwords):
    state = state.copy()
    password = [ ]
    for i in xrange(0, len(known_passwords) + 1):
        password.append(state.solver.BVS('password_%d' % i, 8))
        state.memory.store(0xd0000000 + i, password[-1])

    for i, char in enumerate(known_passwords):
        state.add_constraints(password[i] == ord(char))
    state.memory.store(0x6a3b7c, state.solver.BVV(0, 32))
    state.memory.store(0x6a3b80, state.solver.BVV(0, 32))

    state.regs.rbp = 0xffffffff00000000
    state.memory.store(state.regs.rbp-0x148, state.solver.BVV(0xd0000100, 64), endness=state.arch.memory_endness)
    state.memory.store(state.regs.rbp-0x140, state.solver.BVV(0xd0000100, 64), endness=state.arch.memory_endness)

    return state, password

#
# A bunch of hooks so that I don't have to take care of the following code snippet:
# .text:0000000000457294                 mov     r8, [rbp+var_150]
# .text:000000000045729B                 mov     r8, [r8]
# .text:000000000045729E                 mov     r8, [r8+8]
#
# I can definitely set it up easily with angr, but I was too lazy - which is proved to be
# a mistake soon after...

def hook_rsi(state):
    state.regs.rsi = 0xd0000000

def hook_r8(state):
    state.regs.r8 = 0xd0000000

def hook_rdi(state):
    state.regs.rdi = 0xd0000000

# Calculate the next byte of the password
def calc_one_byte(p, known_passwords, hook_func, start_addr, load_addr1, load_addr2, cmp_flag_reg, cmp_addr):
    byte_pos = len(known_passwords)

    p.hook(load_addr1, UserHook(user_func=hook_func, length=14))
    p.hook(load_addr2, UserHook(user_func=hook_func, length=14))
    state = p.factory.blank_state(addr=start_addr)
    state, password = prepare_state(state, known_passwords)
    sm = p.factory.simulation_manager(state, immutable=False)
    sm.step(4)
    sm.step(size=cmp_addr - load_addr2)

    s0 = sm.active[0].copy()
    s0.add_constraints(getattr(s0.regs, cmp_flag_reg) == 0x1)
    candidates = s0.solver.eval_upto(password[byte_pos], 256)
    # assert len(candidates) == 1

    return chr(candidates[0])

def main():
    p = angr.Project("counter", load_options={'auto_load_libs': False})

    # I got the first letter from gdb and IDA...
    # First letter is 'S'. I found it out at 0x43d2c6
    known_passwords = [ 'S' ]

    # Let's figure out the second letter

    # Get the second char
    c = calc_one_byte(p, known_passwords, hook_rsi, 0x43e099, 0x43e0a8, 0x43e10a, "r11", 0x43e175)
    # Second char: chr(116) == 't'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x43ee79, 0x43ee8c, 0x43eed3, "rbx", 0x43ef38)
    # Third char: chr(52) == '4'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x43fd06, 0x43fd17, 0x43fd6e, "r11", 0x43fde5)
    # Fourth char: chr(116) == 't'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x440a94, 0x440aa7, 0x440b0a, "rbx", 0x440b74)
    # Fifth char: chr(49) == '1'
    known_passwords += [ c ]

    # Why are there so many characters? I was expecting 5 at most...

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x4418e2, 0x4418f1, 0x441942, "r10", 0x441994)
    # Sixth char: chr(99) == 'c'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44268e, 0x44269f, 0x4426d2, "rbx", 0x44274e)
    # Seventh char: chr(95) == '_'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x4433a5, 0x4433b4, 0x4433eb, "r11", 0x443466)
    # Eighth char: chr(52) == '4'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x444194, 0x4441a5, 0x444208, "r11", 0x444260)
    # Ninth char: chr(110) == 'n'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x444f51, 0x444f62, 0x444fa9, "r11", 0x445001)
    # Tenth char: chr(52) == '4'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x445ddc, 0x445ded, 0x445e34, "rbx", 0x445e95)
    # 11th char: chr(108) == 'l'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x446bfa, 0x446c0d, 0x446c64, "rbx", 0x446cd6)
    # chr(121) == 'y'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x4479c4, 0x4479d3, 0x447a0a, "r10", 0x447a7a)
    # chr(83) == 'S'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x44877f, 0x448792, 0x4487cd, "rbx", 0x44883f)
    # chr(49) == '1'
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x449513, 0x449524, 0x44957b, "r11", 0x4495ee)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x44a29d, 0x44a2b0, 0x44a2ff, "rbx", 0x44a357)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44b0e8, 0x44b0f9, 0x44b140, "r11", 0x44b1b3)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x44bded, 0x44bdfc, 0x44be4d, "r10", 0x44bebb)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44cc4f, 0x44cc60, 0x44ccaf, "r11", 0x44ccfb)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44d99f, 0x44d9b0, 0x44da07, "r11", 0x44da72)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44e89a, 0x44e8ab, 0x44e8f4, "r10", 0x44e94a)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x44f67e, 0x44f68f, 0x44f6f2, "r11", 0x44f765)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x4504fe, 0x45050f, 0x450566, "r11", 0x4505bf)
    known_passwords += [ c ]

    # So many letters!!!!!!!!
    c = calc_one_byte(p, known_passwords, hook_r8, 0x4511fe, 0x451211, 0x451268, "r14", 0x4512cd)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x4520d7, 0x4520ea, 0x452117, "r11", 0x45216f)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x452e82, 0x452e91, 0x452ed5, "r11", 0x452f50)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rsi, 0x453d28, 0x453d3a, 0x453d71, "r11", 0x453de6)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x454a39, 0x454a4c, 0x454a95, "r11", 0x454ae7)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x4557f9, 0x45580a, 0x455853, "r11", 0x4558c8)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_rdi, 0x45660a, 0x45661b, 0x456648, "r11", 0x4566a3)
    known_passwords += [ c ]

    c = calc_one_byte(p, known_passwords, hook_r8, 0x457281, 0x457294, 0x4572cf, "rbx", 0x457314)
    known_passwords += [ c ]

    # The last one must be '4'...
    known_passwords += [ '4' ]
    password = "".join(known_passwords)
    print "Flag: EKO{%s}" % password

    return password

def test():
    assert main() == 'St4t1c_4n4lyS1s_randomstring1234'

if __name__ == "__main__":
    main()

