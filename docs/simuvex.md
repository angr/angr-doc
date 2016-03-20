# Semantic Meaning

Most analyses require an understanding of what the code is *doing* (semantic meaning), not just what the code *is* (syntactic meaning).
For this, we developed a module called SimuVEX (https://github.com/angr/simuvex). SimuVEX provides a semantic understanding of what a given piece of VEX code does on a given machine state.

In a nutshell, SimuVEX is a VEX emulator.
Given a machine state and a VEX IR block, SimuVEX provides a resulting machine state (or, in the case of condition jumps, *several* resulting machine states).

## Semantic Translation

SimuVEX's ultimate goal is to provide a semantic meaning to blocks of binary code. Let's grab a motivating example, from the angr testcases.

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

```python
>>> import angr
>>> b = angr.Project("/home/angr/angr/binaries/tests/x86_64/fauxware")
>>> irsb = b.factory.block(0x400664).vex
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
```

This might seem a bit crazy; there's certainly a lot of IR.
As you can see from the assembly, this block sets up the first strcmp call.
While the IR gives us syntactic meaning (i.e., what statements the block containts), SimuVEX can provide us semantic meaning (i.e., what the block *does* to a given state).
We'll now move on to how to do that.

## Accessing SimIRSBs

We get semantic meaning by converting an IRSB into a SimIRSB.
While the former focuses on providing a cross-architecture, programmatically-accessible representation of what a block is, the latter provides a cross-platform, programmatically-accessible representation of what a block did, given an input state.

The supported way of creating SimIRSBs is by using Paths.
Here's an example.

```python
# This creates a SimIRSB at 0x400664, and applies it to a blank state (which is automatically created by blank_path)
>>> p = b.factory.path(addr=0x400664)
>>> p.step()
>>> sirsb = p.next_run

# this is the address of the first instruction in the block
>>> assert sirsb.addr == p.addr
```

Now that we have the SimIRSB, we can retrieve two main pieces of semantic information: what the block did, and where execution will go next.

## SimProcedures

TODO

## Breakpoints!

Like any decent execution engine, SimuVEX supports breakpoints. This is pretty cool! A point is set as follows:

```python
# get our state
>>> import simuvex

>>> s = b.factory.entry_state()

# add a breakpoint. This breakpoint will drop into ipdb right before a memory write happens.
>>> s.inspect.b('mem_write')

# on the other hand, we can have a breakpoint trigger right *after* a memory write happens. On top of that, we
# can have a specific function get run instead of going straight to ipdb.
>>> def debug_func(state):
...     print "State %s is about to do a memory write!"

>>> s.inspect.b('mem_write', when=simuvex.BP_AFTER, action=debug_func)

# or, you can have it drop you in an embedded ipython!
>>> s.inspect.b('mem_write', when=simuvex.BP_AFTER, action='ipython')
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
| call              | A call instruction is hit. |

These events expose different attributes:

| Event type        | Attribute name     | Attribute availability | Attribute meaning                        |
|-------------------|--------------------|------------------------|------------------------------------------|
| mem_read          | mem_read_address   | BP_BEFORE or BP_AFTER  | The address at which memory is being read. |
| mem_read          | mem_read_length    | BP_BEFORE or BP_AFTER  | The length of the memory read. |
| mem_read          | mem_read_expr      | BP_AFTER               | The expression at that address. |
| mem_write         | mem_write_address  | BP_BEFORE or BP_AFTER  | The address at which memory is being written. |
| mem_write         | mem_write_length   | BP_BEFORE or BP_AFTER  | The length of the memory write. |
| mem_write         | mem_write_expr     | BP_BEFORE or BP_AFTER  | The expression that is being written. |
| reg_read          | reg_read_offset    | BP_BEFORE or BP_AFTER  | The offset of the register being read. |
| reg_read          | reg_read_length    | BP_BEFORE or BP_AFTER  | The length of the register read. |
| reg_read          | reg_read_expr      | BP_AFTER               | The expression in the register. |
| reg_write         | reg_write_offset   | BP_BEFORE or BP_AFTER  | The offset of the register being written. |
| reg_write         | reg_write_length   | BP_BEFORE or BP_AFTER  | The length of the register write. |
| reg_write         | reg_write_expr     | BP_BEFORE or BP_AFTER  | The expression that is being written. |
| tmp_read          | tmp_read_num       | BP_BEFORE or BP_AFTER  | The number of the temp being read. |
| tmp_read          | tmp_read_expr      | BP_AFTER               | The expression of the temp. |
| tmp_write         | tmp_write_num      | BP_BEFORE or BP_AFTER  | The number of the temp written. |
| tmp_write         | tmp_write_expr     | BP_AFTER               | The expression written to the temp. |
| expr              | expr               | BP_AFTER               | The value of the expression. |
| statement         | statement          | BP_BEFORE or BP_AFTER  | The index of the IR statement (in the IR basic block). |
| instruction       | instruction        | BP_BEFORE or BP_AFTER  | The address of the native instruction. |
| irsb              | address            | BP_BEFORE or BP_AFTER  | The address of the basic block. |
| constraints       | added_constrints   | BP_BEFORE or BP_AFTER  | The list of contraint expressions being added. |
| call              | function_name      | BP_BEFORE or BP_AFTER  | The name of the function being called. |
| exit              | exit_target        | BP_BEFORE or BP_AFTER  | The expression representing the target of a SimExit. |
| exit              | exit_guard         | BP_BEFORE or BP_AFTER  | The expression representing the guard of a SimExit. |
| exit              | jumpkind           | BP_BEFORE or BP_AFTER  | The expression representing the kind of SimExit. |
| exit              | backtrace          | BP_AFTER               | A list of basic block addresses that were executed in this state's history. |
| symbolic_variable | symbolic_name      | BP_BEFORE or BP_AFTER  | The name of the symbolic variable being created. The solver engine might modify this name (by appending a unique ID and length). Check the symbolic_expr for the final symbolic expression. |
| symbolic_variable | symbolic_size      | BP_BEFORE or BP_AFTER  | The size of the symbolic variable being created. |
| symbolic_variable | symbolic_expr      | BP_AFTER               | The expression representing the new symbolic variable. |

We can put all this together to support conditional breakpoints!
Here it is:

```python
# This will break before a memory write if 0x1000 is a possible value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000)

# This will break before a memory write if 0x1000 is the *only* value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

# This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
>>> s.inspect.b('instruction', when=simuvex.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
```

Cool stuff! In fact, we can even specify a function as a condition:
```python
# this is a complex condition that could do anything! In this case, it makes sure that RAX is 0x41414141 and
# that the basic block starting at 0x8004 was executed sometime in this path's history
>>> def cond(state):
...     return state.any_str(state.regs.rax) == 'AAAA' and 0x8004 in state.inspect.backtrace

>>> s.inspect.b('mem_write', condition=cond)
```

That is some cool stuff!
