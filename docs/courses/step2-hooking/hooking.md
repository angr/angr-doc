# angr courses - step 2 - hooking, path explosion

The binary and source code for this course can be found [here](./).

##### Background: Path explosion
The number of possible paths grows exponentially with every conditional jump (if, while, ...).
As in symbolic execution all active paths have to be tracked, this also results in exponential growth of execution time.

##### Creating path explosion
To simulate path explosion, we are using the function from the collatz conjecture.
It loops until the current value n is 1 and then returns n, meaning that it will either loop forever or return 1.

##### Code example: Hooking
In both cases, we dont want this function to be executed.
We are only interested in the example secret that is printed afterwards if the returned value of the collatz function added to the first command line argument equals 123456.
To exclude it, we simply replace it with a custom function using angr's *hooking* functionality.
For more information visit the [docs](/docs/toplevel.md#hooking)

```python
>>> import angr

# Load the binary
>>> proj = angr.Project('docs/courses/step2-hooking/step2.bin')

# Some important memory locations
>>> addr_collatz_first_instruction = 0x400637
>>> addr_collatz_last_instruction  = 0x40069f
>>> addr_after_print_secret        = 0x40070c

>>> collatz_length = addr_collatz_last_instruction - addr_collatz_first_instruction

# This function will be used as a replacement for the collatz function.
# It takes the current state as an argument and sets the value of its register rax (the return value) to 1
>>> def return1(state):
...    state.regs.rax = 1

# Hook the function above to replace collatz
# When the execution reaches the address of the collatz function, the hooked function will be executed and 'length' bytes of the binary will be skipped
>>> proj.hook(addr_collatz_first_instruction, return1, length=collatz_length)

# Create a new path group to perform symbolic execution
>>> pg = proj.factory.path_group()

# Enabling DEBUG printing lets us see the status of the path group at each step
>>> angr.path_group.l.setLevel("DEBUG")

# Explore the binary, stop when the secret was printed
>>> pg.explore(find=addr_after_print_secret)

# There should be at least one path that found the goal
>>> assert len(pg.found) > 0

# The state of the first path that found the goal
>>> found_state = pg.found[0].state

# Print all strings from I/O with the os to find the string that was printed by the program
>>> for file in found_state.posix.files:
...    print found_state.posix.dumps(file)

The secret is >1234<!
```