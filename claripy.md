# Solver Engine

Angr's solver engine is called Claripy. Claripy exposes the following:

- Claripy ASTs (the claripy.A class) provide a unified way to interact with concrete and symbolic expressions
- Claripy solvers (the claripy.Solver and claripy.CompositeSolver classes) provide a unified interface to constraint solver backends

Internally, Claripy seamlessly mediates the co-operation of multiple disparate backends -- concrete bitvectors, VSA constructs, and SAT solvers. It is pretty badass.

Most users of Angr will not need to interact directly with Claripy (except for, maybe, claripy.A objects) -- SimuVEX handles interactions with Claripy internally. An understanding might be useful.

## Claripy Instances

The main point of interaction with Claripy is the Claripy instance. Several instances, pre-configured with different options, are available by indexing the `claripy.Claripies` dict. They are:

| Object | Description |
|--------|-------------|
| SerialZ3 | This is a Claripy instance that supports constraint solving using Z3. |
| ParallelZ3 | This is a Claripy instance that supports constraint solving using Z3, but parallels out the solves across multiple processors. |
| VSA | This Claripy instance supports VSA constructs for static analysis. |

New Claripy instances can also be created by invoking the `claripy.ClaripyStandalone` class.

## Claripy ASTs

Claripy ASTs abstract away the differences between the constructs that Claripy supports. At their base, they define a tree of operations (i.e., `(a+b)/c`) on any type of underlying data. Claripy handles the application of these operations on the underlying objects themselves.

Currently, Claripy supports the following backend constructs:

| Name | Description | Supported Claripy Instances | Creation Code |
|------|-------------|-----------------------------|---------------|
| BitVecVal | This is a concrete bitvector, representing binary data. It has a value and a size (in bits). | SerialZ3, ParallelZ3, VSA | Create the 4-byte value "AAAA": `claripy_instance.BVV(0x41414141, 32)` |
| BitVec | This is a symbolic bitvector. It has a name and a size (in bits). | SerialZ3, ParallelZ3 | Create a 32-bit symbolic variable "x": `claripy_instance.BV('x', 32)` |
| StridedInterval | This is the "strided interval" construct, from VSA. It has a name, a lower and upper bound, a size (in bits), and a stride. | VSA | Create a strided interval "x" that can be any divisible-by-10 number between 1000 and 2000: `claripy_instance.SI(name='x', bits=32, lower_bound=1000, upper_bound=2000, stride=10)` |
| ValueSet | TODO | VSA | TODO |
| AbstractLocation | TODO | VSA | TODO |
| BoolVal | This is a boolean operation (True or False). | SerialZ3, ParallelZ3, VSA | `claripy_instance.BoolVal(True)`, or `claripy_instance.true` or `claripy_instance.false` |

All of the above creation code returns claripy.AST objects, on which operations can then be carried out. All ASTs involved in an operation must have been created by the same Claripy instance.

ASTs provide several useful operations.

```python
c = claripy.Claripies['SerialZ3']
b = c.BVV(0x41424344, 32)

# Size - you can get the size of an AST with .size()
assert b.size() == 32

# Identity - claripy allows one to test for identity. This is a conservative
# estimation. True means that the objects are definitely identical. False means
# that it's hard to tell (this happens in the presense of constraint solving, for
# example.
assert c.is_identical(b, b)

# Reversing - .reversed is the reversed version of the BVV
assert c.is_identical(b.reversed, c.BVV(0x44434241, 32))
assert b.reversed.reversed is b

# Depth - you can get the depth of the AST
assert b.depth == 0
x = c.BV('x', 32)
assert (x+b).depth == 1
assert ((x+b)/10).depth == 2

# If you want to interact with the underlying object, you can call '.model'.
# Note that, when symbolic variables are involved, this might *still* return an
# AST
assert type(b.model) is claripy.BVV
assert type((x+b).model) is claripy.A # no model is available for symbolic expressions
```

Applying a condition (==, !=, etc) on ASTs will return an AST that represents the condition being carried out.
For example:

```python
r = b == x
assert type(r) is claripy.A

p = b == b
assert type(p) is claripy.A
assert p.model is True
```

You can combine these conditions in different ways.
```python
q = c.And(c.Or(b == x, b * 2 == x, b * 3 == x), x == 0)
assert type(p) is claripy.A
```

The usefulness of this will become apparent when we discuss Claripy solvers.

In general, Claripy supports all of the normal python operations (+, -, |, ==, etc), and provides additional ones via the Claripy instance object. Here's a list of available operations from the latter.

| Name | Description | Example |
|------|-------------|---------|
| LShR | Logically shifts a bit expression (BVV, BV, SI) to the right. | `c.LShR(x, 10)` |
| SignExt | Sign-extends a bit expression. | `c.SignExt(32, x)` or `x.sign_extend(32)` |
| ZeroExt | Zero-extends a bit expression. | `c.ZeroExt(32, x)` or `x.zero_extend(32)` |
| Extract | Extracts the given bits (zero-indexed from the *right*, inclusive) from a bit expression. | Extract the rightmost byte of x: `c.Extract(7, 0, x)` or `x[7:0]` |
| Concat | Concatenates several bit expressions together into a new bit expression. | `c.Concat(x, y, z)` |
| RotateLeft | Rotates a bit expression left. | `c.RotateLeft(x, 8)` |
| RotateRight | Rotates a bit expression right. | `c.RotateRight(x, 8)` |
| Reverse | Reverses a bit expression. | `c.Reverse(x)` or `x.reversed` |
| And | Logical And (on boolean expressions) | `c.And(x == y, x > 0)` |
| Or | Logical Or (on boolean expressions) | `c.Or(x == y, y < 10)` |
| Not | Logical Not (on a boolean expression) | `c.Not(x == y)` is the same as `x != y` |
| If | An If-then-else | Choose the maximum of two expressions: `c.If(x > y, x, y)` |
| is_identical | Check to see if two expressions are identical. | `c.is_identical(x, y)` |
| ULE | Unsigned less than or equal to. | Check if x is less than or equal to y: `c.ULE(x, y)` |
| ULT | Unsigned less than. | Check if x is less than y: `c.ULT(x, y)` |
| UGE | Unsigned greater than or equal to. | Check if x is greater than or equal to y: `c.UGE(x, y)` |
| UGT | Unsigned greater than. | Check if x is greater than y: `c.UGT(x, y)` |

**NOTE:** The default python `>`, `<`, `>=`, and `<=` are signed in Claripy, to reflect their behavior in Z3. You will most likely want to use the unsigned operations, instead.

## Claripy Solvers

Claripy performs constraint solving, via Z3, through the claripy.Solver class. These work much like Z3 solvers:

```python
# create the solver and an expression
c = claripy.Claripies['SerialZ3']
s = c.solver()
x = c.BV('x', 8)

# now let's add a constraint on x
s.add(c.ULT(x, 5)) 

assert sorted(s.eval(x, 10)) == [0, 1, 2, 3, 4]
assert s.max(x) == 4
assert s.min(x) == 0

# we can also get the values of complex expressions
y = c.BVV(65, 8)
z = c.If(x == 1, x, y)
assert sorted(s.eval(z, 10)) == [1, 65] 

# and, of course, we can add constraints on complex expressions
s.add(z % 5 != 0)
assert s.eval(z, 10) == (1,)
assert s.eval(x, 10) == (1,) # interestingly enough, since z can't be y, x can only be 1!
```

## Claripy Backends

Backends are Claripy's workhorses.
Claripy exposes ASTs (claripy.A objects) to the world, but when actual computation has to be done, it pushes those ASTs into objects that can be handled by the backends themselves.
This provides a unified interface to the outside world while allowing Claripy to support different types of computation.
For example, BackendConcrete provides computation support for concrete bitvectors and booleans, BackendVSA introduces VSA constructs such as StridedIntervals (and details what happens when operations are performed on them, and BackendZ3 provides support for symbolic variables and constraint solving.

There are a set of functions that a backend is expected to implement.
For all of these functions, the "public" version is expected to be able to deal with claripy.A objects, while the "private" version should only deal with objects specific to the backend itself.
This is distinguished with Python idioms: a public function will be named func() while a private function will be _func().
All functions should return objects that are usable by the backend in its private methods.
If this can't be done (i.e., some functionality is being attempted that the backend can't handle), the backend should raise a BackendError.
In this case, Claripy will move on to the next backend in its list.

All backends must implement a convert() function.
This function receives a claripy.A and should return an object that the backend can handle in its private methods.
Backends should also implement a _convert() method, which will receive anything that is *not* a claripy.A object (i.e., an integer or an object from a different backend).
If convert() or _convert() receives something that the backend can't translate to a format that is usable internally, the backend should raise BackendError, and thus won't be used for that object.

Claripy contract with its backends is as follows: backends should be able to can handle, in their private functions, any object that they return from their private *or* public functions.
Likewise, Claripy will never pass an object to any backend private function that did not originate as a return value from a private or public function of that backend.
One exception to this is _convert(), as Claripy can try to stuff anything it feels like into _convert() to see if the backend can handle that type of object.
 
### Model Objects and Model Backends

To perform actual, useful computation on ASTs, Claripy uses the concept of model objects.
A model object is a result of the operation represented by the AST.

Examples of model object types that Claripy currently uses are BVVs, StridedIntervals, booleans, ValueSets, and AbstractLocations.
On the contrary, a symbolic BitVec is not a model object, as it cannot be pickled.

### Solver Backends

TODO
