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

# While we're at it, we can do various operations on these bitvectors:
aa = aaaa[31:16] # this extracts the most significant 16 bits
aa00 = aaaa & s.BVV(0xffff0000, 32)
aaab = aaaa + 1
aaaa = s.se.Concat(aaaa, aaaa)

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

This is where we truly start to enter the realm of symbolic expressions. In the above example, the value of `aaaa_or_bbbb` can be, as it implies, either "AAAA" or "BBBB".

## Symbolic Expressions

Symbolic values are expressions that, under different situations, can take on different values. Our symbolic expression, `aaaa_or_bbbb` is a great example of this.  The solver engine provides ways to get at both values:

```python
# this will return a sequence of up to n possible values of the expression in this state.
# in our case, there are only two values, and it'll return [ "AAAA", "BBBB" ]
print "This has 2 values:", s_merged.any_n_str(aaaa_or_bbbb, 2)
print "This *would* have up to 5, but there are only two available:", s_merged.any_n_str(aaaa_or_bbbb, 5)

# there's also the same for the integer value
print s_merged.any_n_int(aaaa_or_bbbb, 2)
```

Of course, there are other ways to encounter symbolic expression than merging. For example, you can create them outright:

```python
# This creates a simple symbolic expression: just a single symbolic bitvector by itself. The bitvector is 32-bits long.
# An auto-incrementing numerical ID, and the size, are appended to the name, since names of symbolic bitvectors must be unique.
v = s.BV("some_name", 32)

# If you want to prevent appending the ID and size to the name, you can, instead, do:
v = s.BV("some_name", 32, explicit_name=True)
```

Symbolic expressions can be interacted with in the same way as normal (concrete) bitvectors. In fact, you can even mix them:

```python
# Create a concrete and a symbolic expression
v = s.BV("some_name", 32)
aaaa = s.BVV(0x41414141, 32)

# Do operations involving them, and retrieve possible numerical solutions
print s.se.any_int(aaaa)
print s.se.any_int(aaaa + v)
print s.se.any_int((aaaa + v) | s.BVV(0xffff0000)

# You can tell between symbolic and concrete expressions fairly easily:
assert s.se.symbolic(v)
assert not s.se.symbolic(aaaa)

# You can even tell *which* variables make up a given expression.
assert s.se.variables(aaaa) == set()
assert s.se.variables(aaaa + v) == { "some_name_1_32" } # that's the ID and size appended to the name
```

As you can see, symbolic and concrete expressions are pretty interchangeable, which is an extremely useful abstraction provided by SimuVEX. You might also notice that, when you read from memory locations that were never written to, you receive symbolic expressions:

```python
# Try it!
m = s.mem_expr(0xbbbb0000, 8)

# The result is symbolic
assert s.se.symbolic(m)

# Along with the ID and length, the address at which this expression originated is also added to the name
assert s.se.variables(m) == { "mem_bbbb0000_2_8" }

# And, of course, we can get the numerical or string solutions for the expression
print s.se.any_n_int(m, 10)
print s.se.any_str(m)
```
So far, we've seen addition being used. But we can do much more. All of the following examples return new expressions, with the operation applied.

```python
# mods aaaa by 0xff, creating an expression, of the same size as aaaa, with all but the last byte zeroed out
aaaa % 0xff

# same effect, but with a bitwise and
aaaa & 0xff

# extracts the most significant (leftmost) byte of aaaa. The range is inclusive on both sides, and indexed with the rightmost bit being 0
aaaa[31:24]

# concatenates aaaa with itself
s.se.Concat(aaaa, aaaa)

# zero-extends aaaa by 32 bits
aaaa.zero_extend(32)

# sign-extends aaaa by 32 bits
aaaa.sign_extend(32)

# shifts aaaa right arithmetically by 8 bits (i.e., sign-extended)
aaaa >> 8

# shifts aaaa right logically by 8 bits (i.e., not sign-extended)
s.se.LShR(aaaa, 8)

# reverses aaaa
aaaa.reverse()

# returns a list of expressions, representing the individual *bits* of aaaa (expressions of length 1)
aaaa.chop()

# same, but for the bytes
aaaa.chop(bits=8)

# and the dwords
aaaa.chop(bits=16)
```

More details on the operations supported by the solver engine are available at the [solver engine's documentation](./claripy.md).

## Symbolic Constraints

Symbolic expressions would be pretty boring on their own. After all, the last few that we created could take *any* numerical value, as they were completely unconstrained. This makes them uninteresting. To spice things up, SimuVEX has the concept of symbolic constraints. Symbolic constraints represent, aptly, constraints (or restrictions) on symbolic expressions. It might be easier to show you:

```python
# make a copy of the state so that we don't screw up the original with our experimentation
s3 = s.copy()

# Let's read some previously untouched section of memory to get a symbolic expression
m = s.mem_expr(0xbbbb0000, 8)

# We can verify that *any* solution would do
assert s3.se.solution(m, 0)
assert s3.se.solution(m, 10)
assert s3.se.solution(m, 20)
assert s3.se.solution(m, 30)
# ... and so on

# Now, let's add a constraint, forcing m to be greater than 10
s3.add_constraints(m > 10)

# We can see the effect of this right away!
assert not s3.se.solution(m, 0)
assert not s3.se.solution(m, 10)
assert s3.se.solution(m, 20)
assert s3.se.solution(m, 30)
```

One cautionary piece of advice is that the comparison operators (`>`, `<`, `>=`, `<=`) are *signed* by default. That means that, in the above example, this is still the case:

```python
# This is actually -1
assert s3.se.solution(m, 0xff)
```

If we want *unsigned* comparisons, we need to use the unsigned versions of the operators (`UGT`, `UGT`, `UGE`, `ULE`).

```python
# Add an unsigned comparison
s3.add_constraints(s3.se.UGT(m, 10))

# We can see the effect of this right away!
assert not s3.se.solution(m, 0)
assert not s3.se.solution(m, 10)
assert s3.se.solution(m, 20)
assert not s3.se.solution(m, 0xff)
```

Amazing. Of course, constraints can be arbitrarily complex:

```python
s3.add_constraints(s3.se.And(s3.se.UGT(m, 10), s3.se.Or(s3.se.ULE(m, 100), m % 200 != 123, s3.se.LShR(m, 8) & 0xff != 0xa)))
```

There's a lot there, but, basically, m has to be greater than 10 *and* either has to be less than 100, or has to be 123 when modded with 200, or, when logically shifted right by 8, the least significant byte must be 0x0a.

## Semantic Translation

The state is great and all, but SimuVEX's ultimate goal is to provide a semantic meaning to blocks of binary code. Let's grab a motivating example, from the angr testcases.

This is the function that we'll be looking at:

	# cat fauxware.c | tail -n+9 | head -n 17
	int authenticate(char *username, char *password)
	{
		char stored_pw[9];
		stored_pw[8] = 0;
		int pwfile;
	
		// evil back d00r
		if (strcmp(password, sneaky) == 0) return 1;
	
		pwfile = open(username, O_RDONLY);
		read(pwfile, stored_pw, 8);
	
		if (strcmp(password, stored_pw) == 0) return 1;
		return 0;
	
	}

Here is the native AMD64 code:

	# objdump -d /home/angr/angr/tests/blob/x86_64/fauxware
	0000000000400664 <authenticate>:
	  400664:	55                   	push   rbp
	  400665:	48 89 e5             	mov    rbp,rsp
	  400668:	48 83 ec 20          	sub    rsp,0x20
	  40066c:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
	  400670:	48 89 75 e0          	mov    QWORD PTR [rbp-0x20],rsi
	  400674:	c6 45 f8 00          	mov    BYTE PTR [rbp-0x8],0x0
	  400678:	48 8b 15 c9 09 20 00 	mov    rdx,QWORD PTR [rip+0x2009c9]        # 601048 <sneaky>
	  40067f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
	  400683:	48 89 d6             	mov    rsi,rdx
	  400686:	48 89 c7             	mov    rdi,rax
	  400689:	e8 c2 fe ff ff       	call   400550 <strcmp@plt>
	  40068e:	85 c0                	test   eax,eax
	  400690:	75 07                	jne    400699 <authenticate+0x35>
	  400692:	b8 01 00 00 00       	mov    eax,0x1
	  400697:	eb 52                	jmp    4006eb <authenticate+0x87>
	  400699:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
	  40069d:	be 00 00 00 00       	mov    esi,0x0
	  4006a2:	48 89 c7             	mov    rdi,rax
	  4006a5:	b8 00 00 00 00       	mov    eax,0x0
	  4006aa:	e8 b1 fe ff ff       	call   400560 <open@plt>
	  4006af:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
	  4006b2:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
	  4006b6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
	  4006b9:	ba 08 00 00 00       	mov    edx,0x8
	  4006be:	48 89 ce             	mov    rsi,rcx
	  4006c1:	89 c7                	mov    edi,eax
	  4006c3:	e8 68 fe ff ff       	call   400530 <read@plt>
	  4006c8:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
	  4006cc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
	  4006d0:	48 89 d6             	mov    rsi,rdx
	  4006d3:	48 89 c7             	mov    rdi,rax
	  4006d6:	e8 75 fe ff ff       	call   400550 <strcmp@plt>
	  4006db:	85 c0                	test   eax,eax
	  4006dd:	75 07                	jne    4006e6 <authenticate+0x82>
	  4006df:	b8 01 00 00 00       	mov    eax,0x1
	  4006e4:	eb 05                	jmp    4006eb <authenticate+0x87>
	  4006e6:	b8 00 00 00 00       	mov    eax,0x0
	  4006eb:	c9                   	leave  
	  4006ec:	c3                   	ret    

And the IR of the first basic block:

	>>> import angr
	>>> p = angr.Project("/home/angr/angr/angr/tests/blob/x86_64/fauxware")
	>>> irsb = p.block(0x400664)
	>>> irsb.pp()
	IRSB {
	   t0:I64   t1:I64   t2:I64   t3:I64   t4:I64   t5:I64   t6:I64   t7:I64
	   t8:I64   t9:I64   t10:I64   t11:I64   t12:I64   t13:I64   t14:I64   t15:I64
	   t16:I64   t17:I64   t18:I64   t19:I64   t20:I64   t21:I64   t22:I64   t23:I64
	   t24:I64   t25:I64   t26:I64   t27:I64   t28:I64   t29:I64   t30:I64   t31:I64
	   t32:I64   
	
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   IR-NoOp
	   ------ IMark(0x400664, 1, 0) ------
	   t0 = GET:I64(56)
	   t13 = GET:I64(48)
	   t12 = Sub64(t13,0x8:I64)
	   t1 = t12
	   PUT(48) = t1
	   STle(t1) = t0
	   PUT(184) = 0x400665:I64
	   ------ IMark(0x400665, 3, 0) ------
	   t14 = GET:I64(48)
	   PUT(56) = t14
	   PUT(184) = 0x400668:I64
	   ------ IMark(0x400668, 4, 0) ------
	   t4 = GET:I64(48)
	   t3 = 0x20:I64
	   t2 = Sub64(t4,t3)
	   PUT(144) = 0x8:I64
	   PUT(152) = t4
	   PUT(160) = t3
	   PUT(48) = t2
	   PUT(184) = 0x40066C:I64
	   ------ IMark(0x40066C, 4, 0) ------
	   t16 = GET:I64(56)
	   t15 = Add64(t16,0xFFFFFFFFFFFFFFE8:I64)
	   t5 = t15
	   t17 = GET:I64(72)
	   STle(t5) = t17
	   PUT(184) = 0x400670:I64
	   ------ IMark(0x400670, 4, 0) ------
	   t19 = GET:I64(56)
	   t18 = Add64(t19,0xFFFFFFFFFFFFFFE0:I64)
	   t6 = t18
	   t20 = GET:I64(64)
	   STle(t6) = t20
	   PUT(184) = 0x400674:I64
	   ------ IMark(0x400674, 4, 0) ------
	   t22 = GET:I64(56)
	   t21 = Add64(t22,0xFFFFFFFFFFFFFFF8:I64)
	   t7 = t21
	   STle(t7) = 0x0:I8
	   PUT(184) = 0x400678:I64
	   ------ IMark(0x400678, 7, 0) ------
	   t8 = Add64(0x40067F:I64,0x2009C9:I64)
	   t23 = LDle:I64(t8)
	   PUT(32) = t23
	   PUT(184) = 0x40067F:I64
	   ------ IMark(0x40067F, 4, 0) ------
	   t25 = GET:I64(56)
	   t24 = Add64(t25,0xFFFFFFFFFFFFFFE0:I64)
	   t9 = t24
	   t26 = LDle:I64(t9)
	   PUT(16) = t26
	   PUT(184) = 0x400683:I64
	   ------ IMark(0x400683, 3, 0) ------
	   t27 = GET:I64(32)
	   PUT(64) = t27
	   PUT(184) = 0x400686:I64
	   ------ IMark(0x400686, 3, 0) ------
	   t28 = GET:I64(16)
	   PUT(72) = t28
	   PUT(184) = 0x400689:I64
	   ------ IMark(0x400689, 5, 0) ------
	   t30 = GET:I64(48)
	   t29 = Sub64(t30,0x8:I64)
	   t10 = t29
	   PUT(48) = t10
	   STle(t10) = 0x40068E:I64
	   t11 = 0x400550:I64
	   t31 = Sub64(t10,0x80:I64)
	   ====== AbiHint(t31, 128, t11) ======
	   PUT(184) = 0x400550:I64
	   t32 = GET:I64(184)
	   PUT(184) = t32; exit-Call
	}

This might seem a bit crazy; there's certainly a lot of IR.
As you can see from the assembly, this block sets up the first strcmp call.
While the IR gives us syntactic meaning (i.e., what statements the block containts), SimuVEX can provide us semantic meaning (i.e., what the block *does* to a given state).
We'll now move on to how to do that.

### Creating a SimIRSB

We get semantic meaning by converting an IRSB into a SimIRSB.
While the former focuses on providing a cross-architecture, programmatically-accessible representation of what a block is, the latter provides a cross-platform, programmatically-accessible representation of what a block did, given an input state.
Here's an example.
In this example, we get the program's initial state (i.e., what we'd expect when the entry point to the program is executed: empty stack, etc), and see what the above block does to it.

```python
import simuvex
sirsb = simuvex.SimIRSB(p.initial_state(), irsb)

# this is the address of the first instruction in the block
print sirsb.addr
```

Now that we have the SimIRSB, we can retrieve two main piece of semantic information: what the block did, and where execution will go next.

### What the block did

SimuVEX exposes the actions of a basic blocks through the concept of "Refs".
There are several different types of refs.
Rather than describe the general concept, we'll just list the specific types:

| Type         | Description |
|--------------|-------------|
| SimTmpWrite  | This represents a write to a VEX temporary variable. |
| SimTmpRead   | This represents a read from a VEX temporary variable. |
| SimRegWrite  | This represents a write into a register. |
| SimRegRead   | This represents a read from a register. |
| SimMemWrite  | This represents a write to memory. |
| SimMemRead   | This represents a read from memory. |
| SimFileWrite | This represents a write to a file. |
| SimFileRead  | this represents a read from a file. |

### Exiting from basic blocks

TODO

### Breakpoints!

Like any decent execution engine, SimuVEX supports breakpoints. This is pretty cool! A point is set as follows:

```python
# get our state
s = p.initial_state()

# add a breakpoint. This breakpoint will drop into ipdb right before a memory write happens.
s.inspect.add_breakpoint('mem_write', simuvex.BP(simuvex.BP_BEFORE))

# on the other hand, we can have a breakpoint trigger right *after* a memory write happens. On top of that, we
# can have a specific function get run instead of going straight to ipdb.
def debug_func(state):
    print "State %s is about to do a memory write!"

s.inspect.add_breakpoint('mem_write', simuvex.BP(simuvex.BP_AFTER, action=debug_func))
```

There are many other places to break than a memory write. Here is the list. You can break at BP_BEFORE or BP_AFTER for each of these events.

| Event type        | Event meaning |
|-------------------|------------------------------------------|
| mem_read          | Memory is being read. |
| mem_write         | Memory is being written. |
| reg_read          | A register is being read. |
| reg_write         | A register is being written. |
| tmp_read          | A temp is being read. |
| tmp_write         | A temp is being written. |
| expr              | An expression is being created (i.e., a result of an arithmetic operation or a constant in the IR). |
| statement         | An IR statement is being translated. |
| instruction       | A new (native) instruction is being translated. |
| irsb              | A new basic block is being translated. |
| constraints       | New constraints are being added to the state. |
| exit              | A SimExit is being created from a SimIRSB. |
| symbolic_variable | A new symbolic variable is being created. |

These events expose different attributes:

| Event type        | Attribute name     | Attribute availability | Attribute meaning                        |
|-------------------|--------------------|------------------------|------------------------------------------|
| mem_read          | mem_read_address   | BP_BEFORE or BP_AFTER  | The address at which memory is being read. |
| mem_read          | mem_read_length    | BP_BEFORE or BP_AFTER  | The length of the memory read. |
| mem_read          | mem_read_expr      | BP_AFTER               | The expression at that address. |
| mem_write         | mem_write_address  | BP_BEFORE or BP_AFTER  | The address at which memory is being written. |
| mem_write         | mem_write_length   | BP_BEFORE or BP_AFTER  | The length of the memory write. |
| mem_write         | mem_write_expr     | BP_BEFORE or BP_AFTER  | The expression that is being written. |
| reg_read          | reg_read_address   | BP_BEFORE or BP_AFTER  | The offset of the register being read. |
| reg_read          | reg_read_length    | BP_BEFORE or BP_AFTER  | The length of the register read. |
| reg_read          | reg_read_expr      | BP_AFTER               | The expression in the register. |
| reg_write         | reg_write_address  | BP_BEFORE or BP_AFTER  | The offset of the register being written. |
| reg_write         | reg_write_length   | BP_BEFORE or BP_AFTER  | The length of the register write. |
| reg_write         | reg_write_expr     | BP_BEFORE or BP_AFTER  | The expression that is being written. |
| tmp_read          | tmp_read_address   | BP_BEFORE or BP_AFTER  | The number of the temp being read. |
| tmp_read          | tmp_read_expr      | BP_AFTER               | The expression of the temp. |
| tmp_write         | tmp_write_address  | BP_BEFORE or BP_AFTER  | The number of the temp written. |
| tmp_write         | tmp_write_expr     | BP_AFTER               | The expression written to the temp. |
| expr              | expr               | BP_AFTER               | The value of the expression. |
| statement         | statement          | BP_BEFORE or BP_AFTER  | The index of the IR statement (in the IR basic block). |
| instruction       | instruction        | BP_BEFORE or BP_AFTER  | The address of the native instruction. |
| irsb              | address            | BP_BEFORE or BP_AFTER  | The address of the basic block. |
| constraints       | added_constrints   | BP_BEFORE or BP_AFTER  | The list of contraint expressions being added. |
| exit              | exit_target        | BP_BEFORE or BP_AFTER  | The expression representing the target of a SimExit. |
| exit              | exit_guard         | BP_BEFORE or BP_AFTER  | The expression representing the guard of a SimExit. |
| exit              | backtrace          | BP_AFTER               | A list of basic block addresses that were executed in this state's history. |
| symbolic_variable | symbolic_name      | BP_BEFORE or BP_AFTER  | The name of the symbolic variable being created. The solver engine might modify this name (by appending a unique ID and length). Check the symbolic_expr for the final symbolic expression. |
| symbolic_variable | symbolic_size      | BP_BEFORE or BP_AFTER  | The size of the symbolic variable being created. |
| symbolic_variable | symbolic_expr      | BP_AFTER               | The expression representing the new symbolic variable. |

We can put all this together to support conditional breakpoints!
Here it is:

```python
# This will break before a memory write if 0x1000 is a possible value of its target expression
s.inspect.add_breakpoint('mem_write', simuvex.BP(simuvex.BP_BEFORE, mem_write_address=0x1000))

# This will break before a memory write if 0x1000 is the *only* value of its target expression
s.inspect.add_breakpoint('mem_write', simuvex.BP(simuvex.BP_BEFORE, mem_write_address=0x1000, mem_write_address_unique=True))

# This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
s.inspect.add_breakpoint('instruction', simuvex.BP(simuvex.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000))
```

Cool stuff! In fact, we can even specify a function as a condition:
```python
# this is a complex condition that could do anything! In this case, it makes sure that RAX is 0x41414141 and
# that the basic block starting at 0x8004 was executed sometime in this path's history
def cond(state):
    return state.any_str(state.reg_expr('rax')) == 'AAAA' and 0x8004 in state.inspect.backtrace
s.inspect.add_breakpoint('mem_write', simuvex.BP(simuvex.BP_BEFORE, condition=cond))
```

That is some cool stuff!
