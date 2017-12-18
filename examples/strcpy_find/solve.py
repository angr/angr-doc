#!/usr/bin/env python
'''
@author Kyle Ossinger (k0ss_sec)
@desc   Tutorial solver for an example program.  I noticed most of the angr
        examples were for solving for a password/flag rather than for finding
        exploitable memory corruptions.  I hope this will lead you on the path
        to finding your own memory corruptions.  Enjoy!

'''

import angr
import claripy  # It is optimal to use claripy.BVV/BVS over state.solver.BVV/BVS
                # EDITOR'S NOTE: this is somewhat true but it super super does
                # not matter if you're just creating a few variables for
                # initialization. do what's convenient. state.solver.BVS will
                # trigger some instrumentation if people have asked to be
                # notified whenever new variables are created, which doesn't
                # usually happen.

def main():
    '''
     Just a helper function to grab function names from resolved symbols.
     This will not be so easy if the binary is stripped.  You will have to
     open the binary in a disassembler and find the addresses of the
     functions you are trying to find/avoid in your paths rather than using
     this helper function.
    '''
    def getFuncAddress( funcName, plt=None ):
        found = [
            addr for addr,func in cfg.kb.functions.iteritems()
            if funcName == func.name and (plt is None or func.is_plt == plt)
            ]
        if len( found ) > 0:
            print "Found "+funcName+"'s address at "+hex(found[0])+"!"
            return found[0]
        else:
            raise Exception("No address found for function : "+funcName)


    def get_byte(s, i):
        pos = s.size() / 8 - 1 - i
        return s[pos * 8 + 7 : pos * 8]

    '''
     load the binary, don't load extra libs to save time/memory from state explosion
    '''
    project = angr.Project("strcpy_test", load_options={'auto_load_libs':False})
    '''
     Set up CFG so we can grab function addresses from symbols.
     I set the fail_fast option to True to minimize how long
     this process takes.
    '''
    cfg = project.analyses.CFG(fail_fast=True)
    '''
     Get addresses of our functions to find or avoid
    '''
    addrStrcpy = getFuncAddress('strcpy', plt=True)
    addrBadFunc = getFuncAddress('func3')
    '''
     Create the list of command-line arguments and add the program name
    '''
    argv = [project.filename]   #argv[0]
    '''
     Add symbolic variable for the password buffer which we are solving for:
    '''
    sym_arg_size = 40   #max number of bytes we'll try to solve for
    '''
     We use 8 * sym_arg_size because the size argument is in BITS, not bytes
    '''
    sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)
    argv.append(sym_arg)    #argv[1]

    '''
     Add the buffer we will copy in if the password is correct
     When we find a path to strcpy, we will check to make sure
     that this is the value that is being copied!
    '''
    argv.append("HAHAHAHA") # argv[2]

    '''
     Initializes an entry state starting at the address of the program entry point
     We simply pass it the same kind of argument vector that would be passed to the
     program, in execv() for example.
    '''
    state = project.factory.entry_state(args=argv)

    '''
     Create a new SimulationManager from the entry state
    '''
    sm = project.factory.simulation_manager(state)

    '''
     Since we want to find a path to strcpy ONLY where we have control of the
     source buffer, we have to have a custom check function which takes a Path
     as an argument.

     You might be wondering what we should do to instruct angr to find our
     target address since we're replacing the 'find=' argument with this
     'check' function.  Just check p.state.ip.args[0] (the current instruction
     pointer) to make sure we're at our intended path destination before checking
     to make sure the other conditions are satisfied.
    '''
    def check(state):
        if (state.ip.args[0] == addrStrcpy):    # Ensure that we're at strcpy
            '''
             By looking at the disassembly, I've found that the pointer to the
             source buffer given to strcpy() is kept in RSI.  Here, we dereference
             the pointer in RSI and grab 8 bytes (len("HAHAHAHA")) from that buffer.
            '''
            BV_strCpySrc = state.memory.load( state.regs.rsi, len(argv[2]) )
            '''
             Now that we have the contents of the source buffer in the form of a bit
             vector, we grab its string representation using the current state's
             solver engine's function "eval" with cast_to set to str so we get a python string.
            '''
            strCpySrc = state.solver.eval( BV_strCpySrc , cast_to=str )
            '''
             Now we simply return True (found path) if we've found a path to strcpy
             where we control the source buffer, or False (keep looking for paths) if we
             don't control the source buffer
            '''
            return True if argv[2] in strCpySrc else False
        else:
            '''
             If we aren't in the strcpy function, we need to tell angr to keep looking
             for new paths.
            '''
            return False
    '''
     Call the function at the entry_state and find a path that satisfies
     the check function.  If you specify a tuple/list/set for find or avoid,
     it translates to an address to find/avoid.  If you just give a function
     it will pass a Path to the function and check to see if the function returns
     True or False and proceed accordingly.

     Here, we tell the explore function to find a path that satisfies our check
     method and avoids any paths that end up in addrBadFunc ('func3')
    '''
    sm = sm.explore(find=check, avoid=(addrBadFunc,))

    found = sm.found
    '''
     Retrieve a concrete value for the password value from the found path.
     If you put this password in the program's first argument, you should be
     able to strcpy() any string you want into the destination buffer and
     cause a segmentation fault if it is too large :)
    '''
    if ( len( found ) > 0 ):    #   Make sure we found a path before giving the solution
        found = sm.found[0]
        result = found.solver.eval(argv[1], cast_to=str)
        try:
            result = result[:result.index('\0')]
        except ValueError:
            pass
    else:   # Aww somehow we didn't find a path.  Time to work on that check() function!
        result = "Couldn't find any paths which satisfied our conditions."
    return result

def test():
    output = main()
    target = "Totally not the password..."
    assert output[:len(target)] == target

if __name__ == "__main__":
    print 'The password is "%s"' % main()
