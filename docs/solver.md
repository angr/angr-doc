# Symbolic Expressions and Constraint Solving

angr's power comes not from it being an emulator, but from being able to execute with what we call _symbolic variables_.
Instead of saying that a variable has a _concrete_ numerical value, we can say that it holds a _symbol_, effectively just a name.
Then, performing arithmetic operations with that variable will yield a tree of operations (termed an _abstract syntax tree_ or _AST_, from compiler theory).
ASTs can be translated into constraints for an _SMT solver_, like z3, in order to ask questions like _"given the output of this sequence of operations, what must the input have been?"_
Here, you'll learn how to use angr to answer this.

## Working with Bitvectors

Let's get a dummy project and state so we can start playing with numbers.

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```

A bitvector is just a sequence of bits, interpreted with the semantics of a bounded integer for arithmetic.
Let's make a few.

```python
# 64-bit bitvectors with concrete values 1 and 100
>>> one = state.solver.BVV(1, 64)
>>> one
 <BV64 0x1>
>>> one_hundred = state.solver.BVV(100, 64)
>>> one_hundred
 <BV64 0x64>

# create a 27-bit bitvector with concrete value 9
>>> weird_nine = state.solver.BVV(9, 27)
>>> weird_nine
<BV27 0x9>
```

As you can see, you can have any sequence of bits and call them a bitvector.
You can do math with them too:

```python
>>> one + one_hundred
<BV64 0x65>

# You can provide normal python integers and they will be coerced to the appropriate type:
>>> one_hundred + 0x100
<BV64 0x164>

# The semantics of normal wrapping arithmetic apply
>>> one_hundred - one*200
<BV64 0xffffffffffffff9c>
```

You _cannot_ say `one + weird_nine`, though.
It is a type error to perform an operation on bitvectors of differing lengths.
You can, however, extend `weird_nine` so it has an appropriate number of bits:

```python
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>
```

`zero_extend` will pad the bitvector on the left with the given number of zero bits.
You can also use `sign_extend` to pad with a duplicate of the highest bit, preserving the value of the bitvector under two's compliment signed integer semantics.

Now, let's introduce some symbols into the mix.

```python
# Create a bitvector symbol named "x" of length 64 bits
>>> x = state.solver.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = state.solver.BVS("y", 64)
>>> y
<BV64 y_10_64>
```

`x` and `y` are now _symbolic variables_, which are kind of like the variables you learned to work with in 7th grade algebra.
Notice that the name you provided has been been mangled by appending an incrementing counter and 
You can do as much arithmetic as you want with them, but you won't get a number back, you'll get an AST instead.

```python
>>> x + one
<BV64 x_9_64 + 0x1>

>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>

>>> x - y
<BV64 x_9_64 - y_10_64>
```

Technically `x` and `y` and even `one` are also ASTs - any bitvector is a tree of operations, even if that tree is only one layer deep.
To understand this, let's learn how to process ASTs.

Each AST has a `.op` and a `.args`.
The op is a string naming the operation being performed, and the args are the values the operation takes as input.
Unless the op is `BVV` or `BVS` (or a few others...), the args are all other ASTs, the tree eventually terminating with BVVs or BVSs.

```python
>>> tree = (x + 1) / (y + 2)
>>> tree
<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
>>> tree.op
'__div__'
>>> tree.args
(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
>>> tree.args[0].op
'__add__'
>>> tree.args[0].args
(<BV64 x_9_64>, <BV64 0x1>)
>>> tree.args[0].args[1].op
'BVV'
>>> tree.args[0].args[1].args
(1, 64)
```

From here on out, we will use the word "bitvector" to refer to any AST whose topmost operation produces a bitvector.
There can be other data types represented through ASTs, including floating point numbers and, as we're about to see, booleans.

## Symbolic Constraints

Performing comparison operations between any two similarly-typed ASTs will yield another AST - not a bitvector, but now a symbolic boolean.

```python
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
>>> one_hundred > 5
<Bool True>
>>> one_hundred > -5
<Bool False>
```

One tidbit you can see from this is that the comparisons are unsigned by default.
The -5 in the last example is coerced to `<BV64 0xfffffffffffffffb>`, which is definitely not less than one hundred.
If you want the comparison to be signed, you can say `one_hundred.SGT(-5)` (that's "signed greater-than").
A full list of operations can be found at the end of this chapter.

This snippet also illustrates an important point about working with angr - you should never directly use a comparison between variables in the condition for an if- or while-statement, since the answer might not have a concrete truth value.
Even if there is a concrete truth value, `if one > one_hundred` will raise an exception.
Instead, you should use `.is_true` and `.is_false`, which test for concrete truthyness/falsiness without performing a constraint solve.

```python
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> yes.is_true()
True
>>> yes.is_false()
False
>>> no.is_true()
False
>>> no.is_false()
True
>>> maybe.is_true()
False
>>> maybe.is_false()
False
```

## Constraint Solving

You can use treat any symbolic boolean as an assertion about the valid values of a symbolic variable by adding it as a _constraint_ to the state.
You can then query for a valid value of a symbolic variable by asking for an evaluation of a symbolic expression.

An example will probably be more clear than an explanation here:

```python
>>> state.add_constraints(x > y)
>>> state.add_constraints(y > 2)
>>> state.add_constraints(10 > x)
>>> state.solver.eval(x)
4
```

By adding these constraints to the state, we've forced the constraint solver to consider them as assertions that must be satisfied about any values it returns.
If you run this code, you might get a different value for x, but that value will definitely be greater than 3 (since y must be greater than 2 and x must be greater than y) and less than 10.
Furthermore, if you then say `state.solver.eval(y)`, you'll get a value of y which is consistent with the value of x that you got.
If you don't add any constraints between two queries, the results will be consistent with each other.

From here, it's easy to see how to do the task we proposed at the beginning of the chapter - finding the input that produced a given output.

```python
# get a fresh state without constraints
>>> state = proj.factory.entry_state()
>>> input = state.solver.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.add_constraints(operation == output)
>>> state.se.eval(input)
0x3333333333333381
```

Note that, again, this solution only works because of the bitvector semantics.
If we were operating over the domain of integers, there would be no solutions!

If we add conflicting or contradictory constraints, such that there are no values that can be assigned to the variables such that the constraints are satisfied, the state becomes _unsatisfiable_, or unsat, and queries against it will raise an exception.
You can check the satisfiability of a state with `state.satisfiable()`.

```python
>>> state.add_constraints(input < 2**32)
>>> state.satisfiable()
False
```

You can also evaluate more complex expressions, not just single variables.

```python
# fresh state
>>> state = proj.factory.entry_state()
>>> state.add_constraints(x - y >= 4)
>>> state.add_constraints(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

From this we can see that `eval` is a general purpose method to convert any bitvector into a python primitive while respecting the integrity of the state.
This is why we use `eval` to convert from concrete bitvectors to python ints, too!

Also note that the x and y variables can be used in this new state despite having been created using an old state.
Variables are not tied to any one state, and can exist freely.

## More Solving Methods

TODO: write this as soon as the new API exists. Include any_n_int, solve-as-string

## Floating point numbers

TODO

## Operations Glossary

#### Arithmetic and Logic

| Name | Description | Example |
|------|-------------|---------|
| LShR | Logically shifts an expression to the right. (the default shifts are arithmetic) | `x.LShR(10)` |
| RotateLeft | Rotates an expression left | `x.RotateLeft(8)` |
| RotateRight | Rotates an expression right | `x.RotateRight(8)` |
| And | Logical And (on boolean expressions) | `solver.And(x == y, x > 0)` |
| Or | Logical Or (on boolean expressions) | `solver.Or(x == y, y < 10)` |
| Not | Logical Not (on a boolean expression) | `solver.Not(x == y)` is the same as `x != y` |
| If | An If-then-else | Choose the maximum of two expressions: `solver.If(x > y, x, y)` |
| ULE | Unsigned less than or equal to | Check if x is less than or equal to y: `x.ULE(y)` |
| ULT | Unsigned less than | Check if x is less than y: `x.ULT(y)` |
| UGE | Unsigned greater than or equal to | Check if x is greater than or equal to y: `x.UGE(y)` |
| UGT | Unsigned greater than | Check if x is greater than y: `x.UGT(y)` |
| SLE | Signed less than or equal to | Check if x is less than or equal to y: `x.SLE(y)` |
| SLT | Signed less than | Check if x is less than y: `x.SLT(y)` |
| SGE | Signed greater than or equal to | Check if x is greater than or equal to y: `x.SGE(y)` |
| SGT | Signed greater than | Check if x is greater than y: `x.SGT(y)` |

#### Bitvector Manipulation


| Name | Description | Example |
|------|-------------|---------|
| SignExt | Pad a bitvector on the left with `n` sign bits | `x.sign_extend(n)` |
| ZeroExt | Pad a bitvector on the left with `n` zero bits | `x.zero_extend(n)` |
| Extract | Extracts the given bits (zero-indexed from the *right*, inclusive) from an expression. | Extract the least significant byte of x: `x[7:0]` |
| Concat | Concatenates any number of expressions together into a new expression. | `x.concat(y, ...)` |

#### Extra Functionality

There's a bunch of prepackaged behavior that you *could* implement by analyzing the ASTs and composing sets of operations, but here's an easier way to do it:

- You can chop a bitvector into a list of chunks of `n` bits with `val.chop(n)`
- You can endian-reverse a bitvector with `x.reversed`
- You can get the width of a bitvector in bits with `val.length`
- You can test if an AST has any symbolic components with `val.symbolic`
- You can get a set of the names of all the symbolic variables implicated in the construction of an AST with `val.variables`
