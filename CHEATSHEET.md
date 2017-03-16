# Intro
The following cheatsheet aims to give a an overview of various things you can do with angr and as a quick reference to check what exactly the syntax for something was without having to dig through the deeper docs.


## General getting started
Some useful imports
```python
import angr #the main framework
import claripy #the solver engine
```

Loading the binary
```python
proj = angr.Project("/path/to/binary", load_options={'auto_load_libs': False} ) # auto_load_libs False for improve performance
```

## Path Groups

Generate a path group object
```python
path_group = proj.factory.path_group(state, threads=4)
```

## Exploring and analysing pathgroups

Choosing a different Exploring strat
```python
path_group.use_technique(angr.exploration_techniques.DFS())
```


Explore Pathgroup until one pathgroup at one of the adresses from find is found
```python
avoid_addr = [0x400c06, 0x400bc7]
find_addr = 0x400c10d
path_group.explore(find=find_addr, avoid=avoid_addr)
```

```python
found = path_group.found[] # The list of paths that reached find condition from explore
found.state.se.any_str(sym_arg) # Return a concrete string value for the sym arg to reach this state 
```

Explore pathgroup until lambda
```python
path_group.step(until=lambda p: p.active[0].addr >= first_jmp)
```
This is especially usefull with the ability to access the current STDOUT or STDERR (1 here is the File Descriptor for STDOUT)
```python
path_group.explore(find=lambda p: "correct" in p.state.posix.dumps(1))
```
Memory Managment on big searches (Auto Drop Stashes):
```python
path_group.explore(find=find_addr, avoid=avoid_addr, step_func=lambda lpg: lpg.drop(stash='avoid'))
```



### Manually Exploring:
```python
path_group.step(step_func=step_func, until=lambda lpg: len(lpg.found) > 0)

def step_func(lpg):
    lpg.stash(filter_func=lambda path: path.addr == 0x400c06, from_stash='active', to_stash='avoid')
    lpg.stash(filter_func=lambda path: path.addr == 0x400bc7, from_stash='active', to_stash='avoid')
    lpg.stash(filter_func=lambda path: path.addr == 0x400c10, from_stash='active', to_stash='found')
    return lpg
```


Enable Logging:
```python
angr.path_group.l.setLevel("DEBUG")
```

### Stashes

Move Stash:
```python
path_group.stash(from_stash="found", to_stash="active")
```
Drop Stashes:
```python
path_group.drop(stash="avoid")
```


## Constraint Solver (claripy)

Create symbolic object
```python
sym_arg_size = 15 #Length in Bytes because we will multiply with 8 later and 
sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size) 
```

Restrict sym_arg to typical char range
```python
for byte in sym_arg.chop(8):
    initial_state.add_constraints(byte != '\x00') # null
    initial_state.add_constraints(byte >= ' ') # '\x20'
    initial_state.add_constraints(byte <= '~') # '\x7e'
```

Use the argument to create a state
```python
argv = [project.filename]
argv.append(sym_arg)
state = project.factory.entry_state(args=argv)
```

Use argument for solving:
```python
argv1 = angr.claripy.BVS("argv1", flag_size * 8)
initial_state = b.factory.full_init_state(args=["./antidebug", argv1], add_options=simuvex.o.unicorn, remove_options={simuvex.o.LAZY_SOLVES})
```

## FFI and Hooking

Calling a function from ipython
```python
f = proj.factory.callable(adress)
f(10)
x=claripy.BVS('x', 64)
f(x) #TODO: Find out how to make that result readable
```

Hooking
```python
hook(addr, hook, length=0, kwargs=None)
```
There are already predefined hooks for libc.so.6 functions (useful for staticly compiled libraries)
```python
hook = simuvex.SimProcedures['libc.so.6']['atoi']
hook(addr, hook, length=4, kwargs=None)
```

Hooking with Simprocedure:
```python
class fixpid(SimProcedure):
    def run(self):
            return 0x30
	 
b.hook(0x4008cd, fixpid, length=5)
```

## Other useful tricks


Drop into an ipython if a ctr+c is recieved (useful for debugging scripts that are running forever)
```python
import signal
def killmyself():
    os.system('kill %d' % os.getpid())
def sigint_handler(signum, frame):
    print 'Stopping Execution for Debug. If you want to kill the programm issue: killmyself()'
    if not "IPython" in sys.modules:
		import IPython
		IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)
```

Get the calltrace of a pathgroup to find out where we got stuck
```python
path = path_group.active[0]
path.callstack_backtrace
```

Get a basic block
```python
block = proj.factory.block(address)
block.capstone.pp() #Capstone object has pretty print and other data about the dissassembly
block.vex.pp()		#Print vex representation
```

## State manipulation

Write to state:
```python
aaaa = claripy.BVV(0x41414141, 32) # 32 = Bits
state.memory.store(0x6021f2, aaaa)
```

Read Pointer to Pointer from Frame:
```python
poi1 = new_state.se.any_int(new_state.regs.rbp)-0x10
poi1 = new_state.se.any_int(new_state.memory.load(poi1, 8, endness='Iend_LE'))
poi1 += 0x8
ptr1 = (new_state.se.any_int(new_state.memory.load(poi1, 8, endness='Iend_LE')))
```

Read from State:
```python
key = []
for i in range(38):
	key.append(extractkey.se.any_int(extractkey.memory.load(0x602140+(i*4), 4, endness='Iend_LE')))
```


## Debugging angr

Set Breakpoint at every Memory read/write:
```python
new_state.inspect.b('mem_read', when=simuvex.BP_AFTER, action=debug_funcRead)
def debug_funcRead(state):
	print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address
```

Set Breakpoint at specific Memory location:
```python
new_state.inspect.b('mem_write', mem_write_address=0x6021f1, when=simuvex.BP_AFTER, action=debug_funcWrite)
```

