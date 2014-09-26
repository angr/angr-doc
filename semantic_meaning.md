# Semantic Meaning

A unified syntactic meaning is great, but most analyses require an understanding of what the code is *doing* (semantic meaning), not just what the code *is* (syntactic meaning). For this, we developed a module called SimuVEX (https://git.seclab.cs.ucsb.edu/gitlab/angr/simuvex). SimuVEX provides a semantic understanding of what a given piece of VEX code does on a given machine state.

In a nutshell, SimuVEX is a VEX emulator. Given an initial machine state and a VEX IR block, SimuVEX provides a resulting machine state (or, in the case of condition jumps, *several* resulting machine states).

## Machine State - memory, registers, and so on

SimuVEX tracks machine states in a `SimState` object. This object tracks the machine's memory, registers, and various other information, such as open files. The "initial" state of program execution (i.e., the state at the entry point) is provided by the angr.Project class, like so:

```python
# make the initial state
s = p.initial_state()

# we can access the memory of the state here
print "The first 5 bytes of the binary are:", s.mem_expr(p.min_addr, 5)

# and the registers, of course
print "The stack pointer starts out as:", s.reg_expr('sp')

# and the temps, although these are currently empty
print "This will throw an except because there is no temp t0, yet:", s.tmp_expr(0)
```

### Accessing Data

The data that's stored in the state (i.e., data in registers, memory, temps, etc) is stored as an internal *expression*. This exposes a single interface to concrete (i.e., `0x41414141`) and symbolic (i.e., "whatever the user might input on stdin") expressions. In fact, this is the core of what enables angr to analyze binaries *symbolically*. However, this complicates matters by not exposing the actual *value*, if it's concrete, directly. For example, if you try the above examples, you will see that the type that is printed is a `claripy.E` type, which is the internal expression representation. Claripy is the solution backend for SimuVEX, and we'll discuss it in more detail later. For now, you might want to know how to get the actual values out of these expressions.

```python
# get the integer value of the content of rax:
print s.se.any_int(s.reg_expr('rax'))

# or, the string value of the 10 bytes stored at 0x1000
print s.se.any_str(s.mem_expr(0x1000, 10))
```

Here, `s.se` is the *solver engine* of the state, which we'll talk about later.

This syntax might seem a bit strange -- we get the expression from the state, and then we pass it back *into* the state to get its actual value. This is, in fact, quite intentional. As we mentioned earlier, these expressions could be either concrete or symbolic. In the case of the latter, a symbolic expression might resolve to two different meanings in two different states. We'll go over symbolic expressions in more detail later on. For now, accept the mystery.

### Storing Data

If you want to store content in the state's memory or registers, you'll need to create an expression out of it. You can do it like so:

```python
# this creates a BVV (which stands for BitVector Value). A BVV is a bitvector that's used to represent data in memory, registers, and temps.
aaaa = s.BVV("AAAA")

# you can create it from an integer, but then you must provide a length (in bits)
aaaa = s.BVV(0x41414141, 32)

# this can then be stored in memory or registers. Since the bitvector
# has a length, only the address to store it at is required
s.store_reg('rax', aaaa)
s.store_mem(0x1000, aaaa)

# of course, you can address memory using expressions as well
s.store_mem(s.reg_expr('rax'), aaaa)
```

For contenience, there are special accessor functions stack operations:

```python
# push our "AAAA" onto the stack
s.stack_push(aaaa)

# and pop it off
aaaa = s.stack_pop()
```

### Copying and Merging

A state supports very fast copies, so that you can explore different possibilities:

```python
s1 = s.copy()
s2 = s.copy()

s1.store_mem(0x1000, s1.BVV("AAAA"))
s2.store_mem(0x1000, s2.BVV("BBBB"))
```

States can also be merged together.

```python
s_merged = s1.merge(s2)

# this is now an expression that can resolve to "AAAA" *or* "BBBB"
aaaa_or_bbbb = s_merged.mem_expr(0x1000, 4)
```

This is where we truly start to enter the realm of symbolic expressions. In the above example, the value of `aaaa_or_bbbb` can be, as it implies, either "AAAA" or "BBBB". The solver engine provides ways to get at both values:

```python
# this will return a sequence of up to n possible values of the expression in this state.
# in our case, there are only two values, and it'll return [ "AAAA", "BBBB" ]
print "This has 2 values:", s_merged.any_n_str(aaaa_or_bbbb, 2)
print "This *would* have up to 5, but there are only two available:", s_merged.any_n_str(aaaa_or_bbbb, 5)

# there's also the same for the integer value
print s_merged.any_n_int(aaaa_or_bbbb, 2)
```

Pretty neat stuff!

