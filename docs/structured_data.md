Working with Data and Conventions
=================================

Frequently, you'll want to access structured data from the program you're analyzing.
angr has several features to make this less of a headache.

## Working with types

SimuVEX has a system for representing types.
These SimTypes are found in `simuvex/s_type.py` - an instance of any of these classes represents a type.
Many of the types are incomplete unless they are supplimented with a SimState - their size depends on the architecture you're running under.
You may do this with `ty.with_state(state)`, which returns a copy of itself, with the state specified.

SimuVEX also has a light wrapper around `pycparser`, which is a C parser.
This helps with getting instances of type objects:

```python
>>> import simuvex

# note that SimType objects have their __repr__ defined to return their c type name,
# so this function actually returned a SimType instance.
>>> simuvex.s_type.parse_type('int')
int

>>> simuvex.s_type.parse_type('char **')
char**

>>> simuvex.s_type.parse_type('struct aa {int x; long y;}')
struct aa

>>> simuvex.s_type.parse_type('struct aa {int x; long y;}').fields
OrderedDict([('x', int), ('y', long)])
```

Additionally, you may parse C defininitions and have them returned to you in a dict:

```python
>>> defs = simuvex.s_type.parse_defns("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
>>> defs
{'list_node': struct llist, 'x': int, 'y': struct llist*}

>>> defs['list_node'].fields
OrderedDict([('str', char*), ('next', struct llist*)])

>>> defs['list_node'].fields['next'].pts_to.fields
OrderedDict([('str', char*), ('next', struct llist*)])

# If you want to get a function type and you don't want to construct it manually,
# you have to use parse_defns, not parse_type
>>> simuvex.s_type.parse_defns("int x(int y, double z);")
{'x': (int, double) -> int}
```

And finally, you can register struct definitions for future use:

```python
>>> simuvex.s_type.define_struct('struct abcd { int x; int y; }')
>>> simuvex.s_type.parse_type('struct abcd')
struct abcd
```

These type objects aren't all that useful on their own, but they can be passed to other parts of angr to specify data types.

## Accessing typed data from memory

If you're reading this book in order, you'll [recall](states.md) that you can retrieve data from memory with `state.memory.load(addr, len, endness=endness)`.
This can get to be a little cumbersome when working with structures, strings, etc.
Instead, there is an alternate interface in `state.mem`, the SimMemView.
This allows you to specify the type of the data you're looking at.

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')
>>> s = b.factory.entry_state()
>>> s.mem[0x601048]
<<untyped> <unresolvable> at 0x601048>

>>> s.mem[0x601048].int
<int (32 bits) <BV32 0x4008d0> at 0x601048>

>>> s.mem[0x601048].long
<long (64 bits) <BV64 0x4008d0> at 0x601048>

>>> s.mem[0x601048].long.resolved
<BV64 0x4008d0>

>>> s.mem[0x601048].long.concrete
4196560L

>>> s.mem[0x601048].deref
<<untyped> <unresolvable> at 0x4008d0>

>>> s.mem[0x601048].deref.string
<string_t <BV64 0x534f534e45414b59> at 0x4008d0>

>>> s.mem[0x601048].deref.string.resolved
<BV64 0x534f534e45414b59>

>>> s.mem[0x601048].deref.string.concrete
'SOSNEAKY'
```

The interface works like this:

- You first use [array index notation] to specify the address you'd like to load from
- If at that address is a pointer, you may access the `deref` property to return a SimMemView at the address present in memory.
- You then specify a type for the data by simply accesing a property of that name.
  For a list of supported types, look at `state.mem.types`.
- You can then _refine_ the type. Any type may support any refinement it likes.
  Right now the only refinements supported are that you may access any member of a struct by its member name, and you may index into a string or array to access that element.
- If the address you specified initially points to an array of that type, you can say `.array(n)` to view the data as an array of n elements.
- Finally, extract the structured data with `.resolved` or `.concrete`.
  `.resolved` will return bitvector values, while `.concrete` will return integer, string, array, etc values, whatever best represents the data.
- Alternately, you may store a value to memory, by assigning to the chain of properties that you've constructed.
  Note that because of the way python works, `x = s.mem[...].prop; x = val` will NOT work, you must say `s.mem[...].prop = val`.

If you define a struct using `s_type.define_struct`, you can access it here as a type:

```python
>>> s.mem[b.entry].abcd
<struct abcd {
  .x = <int (32 bits) <BV32 0x8949ed31> at 0x400580>,
  .y = <int (32 bits) <BV32 0x89485ed1> at 0x400584>
} at 0x400580>
```

## Working with Calling Conventions

A calling convention is the specific means by which code passes arguments and return values through function calls.
While angr comes with a large number of pre-built calling conventions, and a lot of logic for refining calling conventions for specifc circumstances (e.g. floating point arguments need to be stored in different locations, it gets worse from there), it will inevitably be insufficient to describe all possible calling conventions a compiler could generate.
Because of this, you can _customize_ a calling convention by describing where the arguments and return values should live.

angr's abstraction of calling conventions lives in Simuvex as SimCC.
You can construct new SimCC instances through the angr object factory, with `b.factory.cc(...)`.

- Pass as the `args` keyword argument a list of argument storage locations
- Pass as the `ret_val` keyword argument the location where the return value should be stored
- Pass as the `func_ty` keyword argument a SymType for the function prototype.
- Pass it none of these things to use a sane default for the current architecture!

To specify a value location for the `args` or `ret_val` parameters, use instances of the `SimRegArg` or `SimStackArg` classes.
You can find them in the factory - `b.factory.cc.Sim*Arg`.
Register arguments should be instanciated with the name of the register you're storing the value in, and the size of the register in bytes.
Stack arguments should be instanciated with the offset from the stack pointer *at the time of entry into the function* and the size of the storage location, in bytes.

Once you have a SimCC object, you can use it along with a SimState object to extract or store function arguments more cleanly.
Take a look at the [API documentation](http://angr.io/api-doc/simuvex.html#simuvex.s_cc.SimCC) for details.
Alternately, you can pass it to an interface that can use it to modify its own behavior, like `b.factory.call_state`, or...

## Callables

Callables are a Foreign Functions Interface (FFI) for symbolic execution.
Basic callable usage is to create one with `myfunc = b.factory.callable(addr)`, and then call it! `result = myfunc(args, ...)`
When you call the callable, angr will set up a `call_state` at the given address, dump the given arguments into memory, and run a `path_group` based on this state until all the paths have exited from the function.
Then, it merges all the result states together, pulls the return value out of that state, and returns it.

All the interaction with the state happens with the aid of a `SimCC`, to tell where to put the arguments and where to get the return value.
By default, it uses a sane default for the archetecture, but if you'd like to customize it, you can pass a `SimCC` object in the `cc` keyword argument when constructing the callable.

You can pass symbolic data as function arguments, and everything will work fine.
You can even pass more complicated data, like strings, lists, and structures as native python data (use tuples for structures), and it'll be serialized as cleanly as possible into the state.
If you'd like to specify a pointer to a certain value, you can wrap it in a `PointerWrapper` object, available as `b.factory.callable.PointerWrapper`.
The exact semantics of how pointer-wrapping work are a little confusing, but they can be boiled down to "unless you specify it with a PointerWrapper or a specific SimArrayType, nothing will be wrapped in a pointer automatically unless it gets to the end and it hasn't yet been wrapped in a pointer yet and the original type is a string, array, or tuple."
The relevant code is actually in SimCC - it's the `setup_callsite` function.

If you don't care for the actual return value of the call, you can say `func.perform_call(arg, ...)`, and then the properties `func.result_state` and `func.result_path_group` will be populated.
They will actually be populated even if you call the callable normally, but you probably care about them more in this case!
