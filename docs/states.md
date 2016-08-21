# Machine State - memory, registers, and so on

angr (actually, a submodule of angr, called SimuVEX) tracks machine states in a `SimState` object.
This object tracks concrete and/or symbolic values for the machine's memory, registers, along with various other information, such as open files.
You can get a `SimState` by using one of a number of convenient constructors in `Project.factory`.
The different basic states you can construct are described [here](toplevel.md).

```python
>>> import angr, simuvex
>>> b = angr.Project('/bin/true')

# let's get a state at the program entry point:
>>> s = b.factory.entry_state()

# we can access the memory of the state here
>>> print "The first 5 bytes of the binary are:", s.memory.load(b.loader.min_addr(), 5)

# and the registers, of course
>>> print "The stack pointer starts out as:", s.regs.sp
>>> print "The instruction pointer starts out as:", s.regs.ip

# and the temps, although these are currently empty
>>> # print "This will throw an exception because there is no VEX temp t0, yet:", s.scratch.tmp_expr(0)
```

## Accessing Data

The data that's stored in the state (i.e., data in registers, memory, temps, etc) is stored as an internal *expression*. This exposes a single interface to concrete (i.e., `0x41414141`) and symbolic (i.e., "whatever the user might input on stdin") expressions. In fact, this is the core of what enables angr to analyze binaries *symbolically*. However, this complicates matters by not exposing the actual *value*, if it's concrete, directly. For example, if you try the above examples, you will see that the type that is printed is a [claripy AST](claripy.md), which is the internal expression representation. For now, you might want to know how to get the actual values out of these expressions.

```python
# get the integer value of the content of rax:
>>> print s.se.any_int(s.regs.rax)

# or, the string value of the 10 bytes stored at 0x1000
>>> print s.se.any_str(s.memory.load(0x1000, 10))

# get the value of the 4 bytes stored at 0x2000, i.e. a little-endian int
# note that unless otherwise specified, all loads from memory are big-endian by default
>>> print s.se.any_int(s.memory.load(0x2000, 4, endness='Iend_LE'))
```

Here, `s.se` is a [solver engine](claripy.md) that holds the symbolic constraints on the state.

This syntax might seem a bit strange -- we get the expression from the state, and then we pass it back *into* the state to get its actual value. This is, in fact, quite intentional. As we mentioned earlier, these expressions could be either concrete or symbolic. In the case of the latter, a symbolic expression might resolve to two different meanings in two different states. We'll go over symbolic expressions in more detail later on. For now, accept the mystery.

## Storing Data

If you want to store content in the state's memory or registers, you'll need to create an expression out of it. You can do it like so:

```python
# this creates a BVV (which stands for BitVector Value). A BVV is a bitvector that's used to represent
# data in memory, registers, and temps. This BVV represents a 32 bit bitvector of four ascii `A` characters
>>> import claripy
>>> aaaa = claripy.BVV(0x41414141, 32)

# While we're at it, we can do various operations on these bitvectors:
>>> aa = aaaa[31:16] # this extracts the most significant 16 bits
>>> aa00 = aaaa & claripy.BVV(0xffff0000, 32)
>>> aaab = aaaa + 1
>>> aaaaaaaa = claripy.Concat(aaaa, aaaa)

# this can then be stored in memory or registers. Since the bitvector
# has a length, only the address to store it at is required
>>> s.regs.rax = aaaa
>>> s.memory.store(0x1000, aaaa)

# of course, you can address memory using expressions as well
>>> s.memory.store(s.regs.rax, aaaa)
```

For convenience, there are special accessor functions stack operations:

```python
# push our "AAAA" onto the stack
>>> s.stack_push(aaaa)

# and pop it off
>>> aaaa = s.stack_pop()
```

## Copying and Merging

A state supports very fast copies, so that you can explore different possibilities:

```python
>>> s1 = s.copy()
>>> s2 = s.copy()

>>> s1.memory.store(0x1000, s1.se.BVV(0x41414141, 32))
>>> s2.memory.store(0x1000, s2.se.BVV(0x42424242, 32))
```

States can also be merged together.

```python
# merge will return a tuple. the first element is the merged state
# the second element is a symbolic variable describing a state flag
# the third element is a boolean describing whether any merging was done
>>> (s_merged, m, anything_merged) = s1.merge(s2)

# this is now an expression that can resolve to "AAAA" *or* "BBBB"
>>> aaaa_or_bbbb = s_merged.memory.load(0x1000, 4)
```

This is where we truly start to enter the realm of symbolic expressions. In the above example, the value of `aaaa_or_bbbb` can be, as it implies, either "AAAA" or "BBBB".

## Symbolic Expressions

Symbolic values are expressions that, under different situations, can take on different values. Our symbolic expression, `aaaa_or_bbbb` is a great example of this.  The solver engine provides ways to get at both values:

```python
# this will return a sequence of up to n possible values of the expression in this state.
# in our case, there are only two values, and it'll return [ "AAAA", "BBBB" ]
>>> print "This has 2 values:", s_merged.se.any_n_str(aaaa_or_bbbb, 2)
>>> print "This *would* have up to 5, but there are only two available:", s_merged.se.any_n_str(aaaa_or_bbbb, 5)

# there's also the same for the integer value
>>> print s_merged.se.any_n_int(aaaa_or_bbbb, 2)
```

Of course, there are other ways to encounter symbolic expression than merging. For example, you can create them outright:

```python
# This creates a simple symbolic expression: just a single symbolic bitvector by itself. The bitvector is 32-bits long.
# An auto-incrementing numerical ID, and the size, are appended to the name, since names of symbolic bitvectors must be unique.
>>> v = s.se.BVS("some_name", 32)

# If you want to prevent appending the ID and size to the name, you can, instead, do:
>>> v = s.se.BVS("some_name", 32, explicit_name=True)
```

Symbolic expressions can be interacted with in the same way as normal (concrete) bitvectors. In fact, you can even mix them:

```python
# Create a concrete and a symbolic expression
>>> v = s.se.BVS("some_name", 32)
>>> aaaa = s.se.BVV(0x41414141, 32)

# Do operations involving them, and retrieve possible numerical solutions
>>> print s.se.any_int(aaaa)
>>> print s.se.any_int(aaaa + v)
>>> print s.se.any_int((aaaa + v) | s.se.BVV(0xffff0000, 32))

# You can tell between symbolic and concrete expressions fairly easily:
>>> assert s.se.symbolic(v)
>>> assert not s.se.symbolic(aaaa)

# You can even tell *which* variables make up a given expression.
>>> assert s.se.variables(aaaa) == set()
>>> #assert s.se.variables(aaaa + v) == { "some_name_4_32" } # that's the ID and size appended to the name
# This assertion will fail because it depends on precisely the number of symbolic values previously created
```

As you can see, symbolic and concrete expressions are pretty interchangeable, which is an extremely useful abstraction provided by SimuVEX. You might also notice that, when you read from memory locations that were never written to, you receive symbolic expressions:

```python
# Try it!
>>> m = s.memory.load(0xbbbb0000, 8)

# The result is symbolic
>>> assert s.se.symbolic(m)

# Along with the ID and length, the address at which this expression originated is also added to the name
>>> #assert s.se.variables(m) == { "mem_bbbb0000_5_64" }

# And, of course, we can get the numerical or string solutions for the expression
>>> print s.se.any_n_int(m, 10)
>>> print s.se.any_str(m)
```
So far, we've seen addition being used. But we can do much more. All of the following examples return new expressions, with the operation applied.

```python
# mods aaaa by 0x100, creating an expression, of the same size as aaaa, with all but the last byte zeroed out
>>> print aaaa % 0x100

# same effect, but with a bitwise and
>>> print aaaa & 0xff

# extracts the most significant (leftmost) byte of aaaa. The range is inclusive on both sides, and indexed with the rightmost bit being 0
>>> print aaaa[31:24]

# concatenates aaaa with itself
>>> print aaaa.Concat(aaaa)

# zero-extends aaaa by 32 bits
>>> print aaaa.zero_extend(32)

# sign-extends aaaa by 32 bits
>>> print aaaa.sign_extend(32)

# shifts aaaa right arithmetically by 8 bits (i.e., sign-extended)
>>> print aaaa >> 8

# shifts aaaa right logically by 8 bits (i.e., not sign-extended)
>>> print aaaa.LShR(8)

# reverses aaaa, i.e. reverses the order of the bytes as if stored big-endian and loaded little-endian
>>> print aaaa.reversed

# returns a list of expressions, representing the individual *bits* of aaaa (expressions of length 1)
>>> print aaaa.chop()

# same, but for the bytes
>>> print aaaa.chop(bits=8)

# and the dwords
>>> print aaaa.chop(bits=16)
```

More details on the operations supported by the solver engine are available at the [solver engine's documentation](./claripy.md).

## Symbolic Constraints

Symbolic expressions would be pretty boring on their own. After all, the last few that we created could take *any* numerical value, as they were completely unconstrained. This makes them uninteresting. To spice things up, SimuVEX has the concept of symbolic constraints. Symbolic constraints represent, aptly, constraints (or restrictions) on symbolic expressions. It might be easier to show you:

```python
# make a copy of the state so that we don't screw up the original with our experimentation
>>> s3 = s.copy()

# Let's read some previously untouched section of memory to get a symbolic expression
>>> m = s.memory.load(0xbbbb0000, 1)

# We can verify that *any* solution would do
>>> assert s3.se.solution(m, 0)
>>> assert s3.se.solution(m, 10)
>>> assert s3.se.solution(m, 20)
>>> assert s3.se.solution(m, 30)
# ... and so on

# Now, let's add a constraint, forcing m to be less than 10
>>> s3.add_constraints(m < 10)

# We can see the effect of this right away!
>>> assert s3.se.solution(m, 0)
>>> assert s3.se.solution(m, 5)
>>> assert not s3.se.solution(m, 20)
>>> assert not s3.se.solution(m, 30)

# But the constraint does not affect the original state
>>> assert s.se.solution(m, 0)
>>> assert s.se.solution(m, 10)
>>> assert s.se.solution(m, 20)
>>> assert s.se.solution(m, 30)
```

One cautionary piece of advice is that the comparison operators (`>`, `<`, `>=`, `<=`) are *unsigned* by default. That means that, in the above example, this is the case:

```python
# This is actually -1
assert not s3.se.solution(m, 0xff)
```

If we want *signed* comparisons, we need to use the unsigned versions of the operators (`SGT`, `SLT`, `SGE`, `SLE`).
If you'd like to be explicit about your unsigned comparisons, the operators (`UGT`, `ULT`, `UGE`, `ULE`) are available.

```python
# Add an unsigned comparison
>>> s4 = s.copy()
>>> s4.add_constraints(claripy.SLT(m, 10))

# We can see the effect of this right away!
>>> assert s4.se.solution(m, 0)
>>> assert s4.se.solution(m, 5)
>>> assert not s4.se.solution(m, 20)
>>> assert s4.se.solution(m, 0xff)
```

Amazing. Of course, constraints can be arbitrarily complex:

```python
>>> s4.add_constraints(claripy.And(claripy.UGT(m, 10), claripy.Or(claripy.ULE(m, 100), m % 200 != 123, claripy.LShR(m, 8) & 0xff != 0xa)))
```

There's a lot there, but, basically, m has to be greater than 10 *and* either has to be less than 100, or has to be 123 when modded with 200, or, when logically shifted right by 8, the least significant byte must be 0x0a.

## State Options

There are a lot of little tweaks that can be made to the internals of simuvex that will optimize behavior in some situations and be a detriment in others. These tweaks are controlled through state options.

On each SimState object, there is a set (state.options) of all its enabled options. The full domain of options, along with the defaults for different state types, can be found in (s_options.py)[https://github.com/angr/simuvex/blob/master/simuvex/s_options.py], available as `simuvex.o`.

When creating a SimState through any method, you may pass the keyword arguments `add_options` and `remove_options`, which should be sets of options that modify the initial options set from the default.

```python
# Example: enable lazy solves, a behavior that causes state satisfiability to be checked as infrequently as possible.
# This change to the settings will be propogated to all successor states created from this state after this line.
>>> s.options.add(simuvex.o.LAZY_SOLVES)

# Create a new state with lazy solves enabled
>>> s9 = b.factory.entry_state(add_options={simuvex.o.LAZY_SOLVES})
```
