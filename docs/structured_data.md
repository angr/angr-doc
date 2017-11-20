Working with Data and Conventions
=================================

通常来说，你都需要访问你正在分析的程序的结构化数据。Angr 在这个方向上做了一些工作来解决这些难题。

## Working with types

angr 有一个代表类型系统。SimTypes 在 `angr.types` 中，
angr has a system for representing types.
These SimTypes are found in `angr.types` - an instance of any of these classes represents a type.
Many of the types are incomplete unless they are supplamented with a SimState - their size depends on the architecture you're running under.
You may do this with `ty.with_state(state)`, which returns a copy of itself, with the state specified.

angr 也用 C 实现了一个轻量的装饰器 `pycparser`，这有助于获取对象的类型信息

```python
>>> import angr

# note that SimType objects have their __repr__ defined to return their c type name,
# so this function actually returned a SimType instance.
>>> angr.types.parse_type('int')
int

>>> angr.types.parse_type('char **')
char**

>>> angr.types.parse_type('struct aa {int x; long y;}')
struct aa

>>> angr.types.parse_type('struct aa {int x; long y;}').fields
OrderedDict([('x', int), ('y', long)])
```

此外，你也可以解析 C 的定义，无论是变量/函数声明还是自定义的类型都会返回一个字典：

```python
>>> angr.types.parse_defns("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
{'x': int, 'y': struct llist*}

>>> defs = angr.types.parse_types("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
>>> defs
{'list_node': struct llist}

# if you want to get both of these dicts at once, use parse_file, which returns both in a tuple.

>>> defs['list_node'].fields
OrderedDict([('str', char*), ('next', struct llist*)])

>>> defs['list_node'].fields['next'].pts_to.fields
OrderedDict([('str', char*), ('next', struct llist*)])

# If you want to get a function type and you don't want to construct it manually,
# you have to use parse_defns, not parse_type
>>> angr.types.parse_defns("int x(int y, double z);")
{'x': (int, double) -> int}
```

最后，你可以自己定义数据结构以供使用：

```python
>>> angr.types.define_struct('struct abcd { int x; int y; }')
>>> angr.types.register_types(angr.types.parse_types('typedef long time_t;'))
>>> angr.types.parse_defns('struct abcd a; time_t b;')
{'a': struct abcd, 'b': long}
```

这些类型对象本身并没什么用，不过可以传递给 angr 的其他组件来指定数据类型

## 访问内存中指定类型的数据

既然已经知道了 angr 的类型系统是如何工作的，现在可以解锁 `state.mem` 接口的全部功能了！
任何在类型模块中注册过的类型都可以用于从内存中提取数据

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')
>>> s = b.factory.entry_state()
>>> s.mem[0x601048]
<<untyped> <unresolvable> at 0x601048>

>>> s.mem[0x601048].long
<long (64 bits) <BV64 0x4008d0> at 0x601048>

>>> s.mem[0x601048].long.resolved
<BV64 0x4008d0>

>>> s.mem[0x601048].long.concrete
0x4008d0

>>> s.mem[0x601048].abcd
<struct abcd {
  .x = <int (32 bits) <BV32 0x4008d0> at 0x601048>,
  .y = <int (32 bits) <BV32 0x0> at 0x60104c>
} at 0x601048>

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

接口如下：

- 首先使用 [数组索引] 来指定要加载的地址
- 如果该地址是一个指针，可以通过 `deref` 属性返回 SimMemView 在内存中的地址
- 可以通过访问属性指定数据的类型。支持类型的列表请参见： `state.mem.types`
- 可以 _重定义_ 类型，任何类型都支持任意重定义。现在唯一支持的重定义就是通过成员名访问结构体中的任何成员，并且也可以使用对字符串/数组的索引来访问元素  
- 如果如果初始给定的地址指向一个类型的数组，可以将
 `.array(n)` 看作由n个元素组成的数组
- 最后，使用 `.resolved` 或者 `.concrete` 提取结构化数据
  `.resolved` 将返回 bitvector，而 `.concrete` 返回整型、字符串、数组等能代表数据的类型的值
- 或者，也可以通过分配自定义的属性链将值存储到内存中
  请注意，由于 Python 的限制，`x = s.mem[...].prop; x = val` 这样的写法不被允许，必须使用 `s.mem[...].prop = val` 才能成功

如果你使用 `define_struct` 或 `register_types` 定义一个结构，就可以作为一个类型来访问它

```python
>>> s.mem[b.entry].abcd
<struct abcd {
  .x = <int (32 bits) <BV32 0x8949ed31> at 0x400580>,
  .y = <int (32 bits) <BV32 0x89485ed1> at 0x400584>
} at 0x400580>
```

## 使用调用约定Working with Calling Conventions

调用约定
A calling convention is the specific means by which code passes arguments and return values through function calls.
While angr comes with a large number of pre-built calling conventions, and a lot of logic for refining calling conventions for specific circumstances (e.g. floating point arguments need to be stored in different locations, it gets worse from there), it will inevitably be insufficient to describe all possible calling conventions a compiler could generate.
Because of this, you can _customize_ a calling convention by describing where the arguments and return values should live.

angr's abstraction of calling conventions is called SimCC.
You can construct new SimCC instances through the angr object factory, with `b.factory.cc(...)`.

- Pass as the `args` keyword argument a list of argument storage locations
- Pass as the `ret_val` keyword argument the location where the return value should be stored
- Pass as the `func_ty` keyword argument a SymType for the function prototype.
- Pass it none of these things to use a sane default for the current architecture!

To specify a value location for the `args` or `ret_val` parameters, use instances of the `SimRegArg` or `SimStackArg` classes.
You can find them in the factory - `b.factory.cc.Sim*Arg`.
Register arguments should be instantiated with the name of the register you're storing the value in, and the size of the register in bytes.
Stack arguments should be instantiated with the offset from the stack pointer *at the time of entry into the function* and the size of the storage location, in bytes.

Once you have a SimCC object, you can use it along with a SimState object to extract or store function arguments more cleanly.
Take a look at the [API documentation](http://angr.io/api-doc/angr.html#angr.calling_conventions.SimCC) for details.
Alternately, you can pass it to an interface that can use it to modify its own behavior, like `b.factory.call_state`, or...

## Callables

<a name=callables></a>

Callables are a Foreign Functions Interface (FFI) for symbolic execution.
Basic callable usage is to create one with `myfunc = b.factory.callable(addr)`, and then call it! `result = myfunc(args, ...)`
When you call the callable, angr will set up a `call_state` at the given address, dump the given arguments into memory, and run a `path_group` based on this state until all the paths have exited from the function.
Then, it merges all the result states together, pulls the return value out of that state, and returns it.

All the interaction with the state happens with the aid of a `SimCC`, to tell where to put the arguments and where to get the return value.
By default, it uses a sane default for the architecture, but if you'd like to customize it, you can pass a `SimCC` object in the `cc` keyword argument when constructing the callable.

You can pass symbolic data as function arguments, and everything will work fine.
You can even pass more complicated data, like strings, lists, and structures as native python data (use tuples for structures), and it'll be serialized as cleanly as possible into the state.
If you'd like to specify a pointer to a certain value, you can wrap it in a `PointerWrapper` object, available as `b.factory.callable.PointerWrapper`.
The exact semantics of how pointer-wrapping work are a little confusing, but they can be boiled down to "unless you specify it with a PointerWrapper or a specific SimArrayType, nothing will be wrapped in a pointer automatically unless it gets to the end and it hasn't yet been wrapped in a pointer yet and the original type is a string, array, or tuple."
The relevant code is actually in SimCC - it's the `setup_callsite` function.

If you don't care for the actual return value of the call, you can say `func.perform_call(arg, ...)`, and then the properties `func.result_state` and `func.result_path_group` will be populated.
They will actually be populated even if you call the callable normally, but you probably care about them more in this case!
