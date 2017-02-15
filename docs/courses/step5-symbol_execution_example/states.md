# angr courses - step 5 - finding correct input, SimState

The binary for this course can be found [here](./).

##### Background: SimState
Angr's module SimuVEX provides the SimState which is used to represent every state of a program while symbolically executing it.
The state holds e.g. values of registers and memory, a Solver and the system state like open files or sockets.
Every state also knows its successor states.


In this course, we will take a look at the binary that was also used in [the previous course about CFGs](/docs/courses/step4-control_flow_graphs/cfg.md).
We already found out by looking at the CFG that it takes some user input, performs some math operations on it and checks the results against some hardcoded constants.
Afterwards, it prints something to the user.

We want to find the correct input, so we first have to find a way to determine whether the input was correct.
To find out what strings the binary might print, we take a look at the .rodata section of the binary:
`$ objdump --section .rodata --source step5.bin`

Now we can define functions to test which string was printed to the user:
```python
>>> def correct(path):
...    return "Congratz" in path.state.posix.dumps(1)

>>> def incorrect(path):
...    return "Nope" in path.state.posix.dumps(1)
```

As analyzing the whole binary from the start - and therefore also analyzing the b64d function - takes too long, we want start the execution at some point afterwards.
To do that we have to create a blank state that serves as a starting point to the execution.
It can be seen in the CFG, that the user input is stored at the memory address specified in register r9, so it has to be set to some memory region.
As execution in angr is only simulated a value like 0x42 is fine and will not result in a segfault.
```python
>>> SOME_MEMORY_ADDR = 0x42

>>> init_state = proj.factory.blank_state(addr=0x400843)
>>> init_state.regs.rcx = 0
>>> init_state.regs.rsi = 0
>>> init_state.regs.rdi = 0
>>> init_state.regs.r10 = 0
>>> init_state.regs.r9 = SOME_MEMORY_ADDR
>>> init_state.regs.r8 = 0
```

Now the path group can be created basing on that state.
The logging level is set to DEBUG so the progress of the path group can be seen.
The functions specified before can now be used to tell the path group what to find/avoid.
```python
>>> angr.path_group.l.setLevel("DEBUG")
>>> pg = proj.factory.path_group(init_state)
>>> pg.explore(find=correct, avoid=incorrect)
>>> print pg
<PathGroup with 4 avoid, 1 found>
```

One path reached the state where the success message is printed to the user.
We use that state to get the symbolic variable that represents the user input.
By passing that variable back to the state and its solver, a concrete value can be figured out.
As we started the execution after the call to base64 decode, the "user input" we found has to be base64 encoded so we get a base64 string that can be passed to the real binary.
```python
>>> found_state = pg.found[0].state
>>> symbolic_input_string = found_state.memory.load(SOME_MEMORY_ADDR, 16)
>>> concrete_input_string = found_state.se.any_str(symbolic_input_string)

>>> import base64
>>> print base64.b64encode(concrete_input_string)
PFVweE7IBZBJgsulkxZVyw==
```

Using that input for the real binary, the success message "Congratz, you win!" is printed.