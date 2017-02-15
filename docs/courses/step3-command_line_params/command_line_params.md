# angr courses - step 3 - symbolic command line parameters and constraints on them

The binary and source code for this course can be found [here](./).

##### The binary for this tutorial
The binary that we want to analyze expects one command line parameter (argv) when executed.
If the parameter fulfiss certain criteria, a success string is printed.
Imagine it as a login process that you want to crack.

##### Background: Concept of symbolic values
As we and angr dont know the correct password, this value is fully symbolic, meaning that it can have any value in the beginning.
Look at the following C example.
When analyzing the corresponding binary with angr, at state *a*, argv[1] is fully symbolic.
Due to the if-statement the active path splits into two paths:
* In the first path (if-condition is true, *b*), the constraint that argv[1] equals "test" is added.
* In the second path (if-condition is false, *c*), the negation is added: argv[1] does not equal "test".
```c
int main(int argc, char** argv) {
	// a
	if(strcmp(argv[1], "test") == 0) {
		// b
	} else {
		// c
	}
}
```
For more information visit the [docs](docs/claripy.md).

##### Background: Concretizing symbolic values in angr
Let's say that there is something important at *b* and we want to know what parameter to pass the binary to get there.
In angr we can simply query the solver engine of the current state for any value that the constrained symbolic variable might have.
In the following example, a bitvector consisting of 32 symbolic bits is used.
```python
>>> some_symbolic_variable = claripy.BVS("some_name", 8 * 4)
>>> print state.se.any_str(some_symbolic_variable)
```
Note that the symbolic variable is dependent on a state, as different states of the program have different constraints on the symbolic variables (compare the state at *a* to the state at *b*).

##### Code example: Finding correct parameters


```python
>>> import angr
>>> import claripy

# Load the binary
>>> proj = angr.Project("docs/courses/step3-command_line_params/step3.bin")

# Find address of function puts (printf)
# A CFG is needed that finds functions and stores them in the knowledge base (kb)
>>> proj.analyses.CFG()
>>> addr_puts = proj.kb.functions.function(name="puts").addr

# Create the symbolic bitvector using claripy
# As a char consists of 8 bits, we need to multiply the number of chars with 8
>>> num_input_chars = 50
>>> input_str = claripy.BVS("argv1", 8 * num_input_chars)

# Create the initial state that sets the specified command line params
>>> init_state = proj.factory.entry_state(args=["docs/courses/step3-command_line_params/step3.bin", input_str])

# Limit the param to alphanumerical characters (a-z, A-Z, 0-9)
# To do that, we have to add a constraint to every byte of the symbolic bitvector
# claripy.Or/claripy.And are the logical or/and
>>> for i in xrange(num_input_chars):
...     current_byte = input_str.get_byte(i)
...     init_state.add_constraints(
...         claripy.Or(
...             claripy.And(current_byte >= 'a', current_byte <= 'z'),
...             claripy.And(current_byte >= 'A', current_byte <= 'Z'),
...             claripy.And(current_byte >= '0', current_byte <= '9')
...         )
...     )

# Create a pathgroup starting at the created initial state
>>> pg = proj.factory.path_group(init_state)

# Explore until the console output is found
>>> pg.explore(find=addr_puts)

# At least one path should have found the output
>>> assert len(pg.found) > 0

# The state of the first path that found the goal address
>>> found_state = pg.found[0].state

# Evaluate the symbolic input string in the goal state to find possible inputs that led to the goal
>>> possible_inputs = found_state.se.any_n_str(input_str, 20)

# Print them
>>> for input in possible_inputs:
...     print input
```