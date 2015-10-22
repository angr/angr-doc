# Solver Engine

Angr's solver engine is called Claripy. Claripy exposes the following:

- Claripy ASTs (the subclasses of claripy.ast.Base) provide a unified way to interact with concrete and symbolic expressions
- Claripy frontends provide a unified interface to expression resolution (including constraint solving) over different backends

Internally, Claripy seamlessly mediates the co-operation of multiple disparate backends -- concrete bitvectors, VSA constructs, and SAT solvers. It is pretty badass.

Most users of Angr will not need to interact directly with Claripy (except for, maybe, claripy AST objects, which represent symbolic expressions) -- SimuVEX handles most interactions with Claripy internally.
However, for dealing with expressions, an understanding of Claripy might be useful.

## Frontends

The main point of interaction with Claripy are the Claripy frontends.
These frontends interact with the backends in different ways.
For example, the `FullFrontend` is a frontend to support backends that must track state (i.e., such as the Z3 backend, which tracks state in the way of a Z3 constraint solver object).
On the other hand, `LightFrontend` is a faster frontend, designed for backends that do not track state (i.e., the VSA backend or the purely concrete backend).
Additionally, `CompositeFrontend` extends on `FullFrontend`, implementing optimizations that solve smaller sets of constraints to speed up constraint solving.

For symbolic uses, the `claripy.Solver()` function will create a Z3-backed `FullFrontend`.
This is the entry-point to Claripy for most users.

## Claripy ASTs

Claripy ASTs abstract away the differences between the constructs that Claripy supports.
They define a tree of operations (i.e., `(a+b)/c`) on any type of underlying data.
Claripy handles the application of these operations on the underlying objects themselves by dispatching requests to the backends.

Currently, Claripy supports the following types of ASTs:

| Name | Description | Supported By (Claripy Backends) | Example Code |
|------|-------------|-----------------------------|---------------|
| BV | This is a bitvector, whether symbolic (with a name) or concrete (with a value). It has a size (in bits). | BackendConcrete, BackendVSA, BackendZ3 | Create a 32-bit symbolic bitvector "x": `claripy.BV('x', 32)`. Create a 32-bit bitvectory with the value `0xc001b3475`: `claripy.BVV(0xc001b3a75, 32)`. Create a 32-bit "strided interval" (see VSA documentation) that can be any divisible-by-10 number between 1000 and 2000: `claripy.SI(name='x', bits=32, lower_bound=1000, upper_bound=2000, stride=10)`  |
| FP | This is a floating-point number, whether symbolic (with a name) or concrete (with a value). | BackendConcrete, BackendZ3 | TODO  |
| Bool | This is a boolean operation (True or False). | BackendConcrete, BackendVSA, BackendZ3 | `claripy.BoolVal(True)`, or `claripy.true` or `claripy.false`, or by comparing two ASTs (i.e., `claripy.BV('x', 32) < claripy.BV('y', 32)` |

All of the above creation code returns claripy.AST objects, on which operations can then be carried out.

ASTs provide several useful operations.

```python
>>> import claripy

>>> bv = claripy.BVV(0x41424344, 32)

# Size - you can get the size of an AST with .size()
>>> assert bv.size() == 32

# Identity - claripy allows one to test for identity. This is a conservative
# estimation. True means that the objects are definitely identical. False means
# that it's hard to tell (this happens in the presense of constraint solving, for
# example.
>>> assert claripy.is_identical(bv, bv)

# Reversing - .reversed is the reversed version of the BVV
>>> assert claripy.is_identical(bv.reversed, claripy.BVV(0x44434241, 32))
>>> # assert bv.reversed.reversed is bv
# TODO: FUCKING FIX THIS

# Depth - you can get the depth of the AST
>>> print bv.depth
>>> assert bv.depth == 2
>>> x = claripy.BV('x', 32)
>>> assert (x+bv).depth == 3
>>> assert ((x+bv)/10).depth == 4
# TODO: ALSO FUCKING FIX THIS

# If you want to interact with the underlying object, you can call '.model'.
# Note that, when symbolic variables are involved, this might *still* return an
# AST
>>> assert type(bv.model) is claripy.bv.BVV # not to be confused with claripy.BVV, claripy.bv.BVV is a python concrete bitvector representation
>>> assert isinstance((x+bv).model, claripy.ast.Base) # no model is available for symbolic expressions
```

Applying a condition (==, !=, etc) on ASTs will return an AST that represents the condition being carried out.
For example:

```python
>>> r = bv == x
>>> assert isinstance(r, claripy.ast.Bool)

>>> p = bv == bv
>>> assert isinstance(p, claripy.ast.Bool)
>>> assert p.model is True
```

You can combine these conditions in different ways.
```python
>>> q = claripy.And(claripy.Or(bv == x, bv * 2 == x, bv * 3 == x), x == 0)
>>> assert isinstance(p, claripy.ast.Bool)
```

The usefulness of this will become apparent when we discuss Claripy solvers.

In general, Claripy supports all of the normal python operations (+, -, |, ==, etc), and provides additional ones via the Claripy instance object. Here's a list of available operations from the latter.

| Name | Description | Example |
|------|-------------|---------|
| LShR | Logically shifts a bit expression (BVV, BV, SI) to the right. | `claripy.LShR(x, 10)` |
| SignExt | Sign-extends a bit expression. | `claripy.SignExt(32, x)` or `x.sign_extend(32)` |
| ZeroExt | Zero-extends a bit expression. | `claripy.ZeroExt(32, x)` or `x.zero_extend(32)` |
| Extract | Extracts the given bits (zero-indexed from the *right*, inclusive) from a bit expression. | Extract the rightmost byte of x: `claripy.Extract(7, 0, x)` or `x[7:0]` |
| Concat | Concatenates several bit expressions together into a new bit expression. | `claripy.Concat(x, y, z)` |
| RotateLeft | Rotates a bit expression left. | `claripy.RotateLeft(x, 8)` |
| RotateRight | Rotates a bit expression right. | `claripy.RotateRight(x, 8)` |
| Reverse | Reverses a bit expression. | `claripy.Reverse(x)` or `x.reversed` |
| And | Logical And (on boolean expressions) | `claripy.And(x == y, x > 0)` |
| Or | Logical Or (on boolean expressions) | `claripy.Or(x == y, y < 10)` |
| Not | Logical Not (on a boolean expression) | `claripy.Not(x == y)` is the same as `x != y` |
| If | An If-then-else | Choose the maximum of two expressions: `claripy.If(x > y, x, y)` |
| is_identical | Check to see if two expressions are identical. | `claripy.is_identical(x, y)` |
| ULE | Unsigned less than or equal to. | Check if x is less than or equal to y: `claripy.ULE(x, y)` |
| ULT | Unsigned less than. | Check if x is less than y: `claripy.ULT(x, y)` |
| UGE | Unsigned greater than or equal to. | Check if x is greater than or equal to y: `claripy.UGE(x, y)` |
| UGT | Unsigned greater than. | Check if x is greater than y: `claripy.UGT(x, y)` |

**NOTE:** The default python `>`, `<`, `>=`, and `<=` are signed in Claripy, to reflect their behavior in Z3. You will most likely want to use the unsigned operations, instead.

## Claripy Solvers

Claripy performs constraint solving, via Z3, through the claripy.Solver class. These work much like Z3 solvers:

```python
# create the solver and an expression
>>> s = claripy.Solver()
>>> x = claripy.BV('x', 8)

# now let's add a constraint on x
>>> s.add(claripy.ULT(x, 5)) 

>>> assert sorted(s.eval(x, 10)) == [0, 1, 2, 3, 4]
>>> assert s.max(x) == 4
>>> assert s.min(x) == 0

# we can also get the values of complex expressions
>>> y = claripy.BVV(65, 8)
>>> z = claripy.If(x == 1, x, y)
>>> assert sorted(s.eval(z, 10)) == [1, 65] 

# and, of course, we can add constraints on complex expressions
>>> s.add(z % 5 != 0)
>>> assert s.eval(z, 10) == (1,)
>>> assert s.eval(x, 10) == (1,) # interestingly enough, since z can't be y, x can only be 1!
```

## Claripy Backends

Backends are Claripy's workhorses.
Claripy exposes ASTs to the world, but when actual computation has to be done, it pushes those ASTs into objects that can be handled by the backends themselves.
This provides a unified interface to the outside world while allowing Claripy to support different types of computation.
For example, BackendConcrete provides computation support for concrete bitvectors and booleans, BackendVSA introduces VSA constructs such as StridedIntervals (and details what happens when operations are performed on them, and BackendZ3 provides support for symbolic variables and constraint solving.

There are a set of functions that a backend is expected to implement.
For all of these functions, the "public" version is expected to be able to deal with claripy's AST objects, while the "private" version should only deal with objects specific to the backend itself.
This is distinguished with Python idioms: a public function will be named func() while a private function will be _func().
All functions should return objects that are usable by the backend in its private methods.
If this can't be done (i.e., some functionality is being attempted that the backend can't handle), the backend should raise a BackendError.
In this case, Claripy will move on to the next backend in its list.

All backends must implement a `convert()` function.
This function receives a claripy AST and should return an object that the backend can handle in its private methods.
Backends should also implement a `_convert()` method, which will receive anything that is *not* a claripy AST object (i.e., an integer or an object from a different backend).
If `convert()` or `_convert()` receives something that the backend can't translate to a format that is usable internally, the backend should raise BackendError, and thus won't be used for that object.
All backends must also implement any functions of the base `Backend` abstract class that currently raise `NotImplementedError()`.

Claripy's contract with its backends is as follows: backends should be able to handle, in their private functions, any object that they return from their private *or* public functions.
Claripy will never pass an object to any backend private function that did not originate as a return value from a private or public function of that backend.
One exception to this is `convert()` and `_convert()`, as Claripy can try to stuff anything it feels like into _convert() to see if the backend can handle that type of object.
 
### Model Objects

To perform actual, useful computation on ASTs, Claripy uses model objects.
A model object is a result of the operation represented by the AST.
Claripy expects these objects to be returned from the backends, and will pass such objects into that backend's other functions.
