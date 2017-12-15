使用数据与约定
=================================

通常来说，你都需要访问你正在分析的程序的结构化数据。Angr 在这个方向上做了一些工作来解决这些难题。

## 类型

angr 有一个代表类型系统。SimTypes 在 `angr.types` 中，类中的任何实例都可以代表一种类型。
许多类型都不完整，除非被 SimState 替代。类型的宽度大小往往取决于运行机器的体系结构。
也可以使用 `ty.with_state(state)` 来返回它自身指定状态的一个副本

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

## 使用调用约定

调用约定是通过函数传递参数和返回值的特殊方法。
虽然 angr 带有大量预设的调用约定，并且在特定情况下（例如，浮点指针参数需要存储在不同的位置）有很多改进调用约定的地方。但是不可避免地不足以描述编译器可能产生的所有调用约定。因此，angr 支持通过描述参数与返回值的位置自定义调用约定

angr 对调用约定的抽象是 SimCC。
可以通过 angr 的对象工厂来构建一个新的 SimCC 示例，例如 `b.factory.cc(...)`

- 使用参数 `args` 传递参数存储位置的列表
- 使用参数 `ret_val` 传递返回值存储位置的列表
- 使用参数 `func_ty` 传递函数原型的 SymType
- 不使用参数则默认为当前架构的默认值

要指定 `args` 或 `ret_val` 参数值的位置，要使用 `SimRegArg` 或者 `SimStackArg` 类的实例。
也可以在工厂中实现 `b.factory.cc.Sim*Arg`。
寄存器参数应该使用正在存储值的寄存器的名字与寄存器的大小（以字节为单位）来进行实例化。
使用*进入函数时*堆栈指针的偏移量和存储位置的大小（以字节为单位）来实例化堆栈参数

一旦创建了一个 SimCC 对象，就可以和 SimState 对象联合使用来提取/存储函数参数。详见
 [API 文档](http://angr.io/api-doc/angr.html#angr.calling_conventions.SimCC)。
或者可以传递给一个接口，接口可以使用这个对象来修改它自身的行为，比如 `b.factory.call_state`

## 可调用对象

<a name=callables></a>

可调用对象是符号执行的外部函数接口（FFI）。
简单可调用对象的用法：先使用 `myfunc = b.factory.callable(addr)` 创建一个可调用对象。之后就可以使用 `result = myfunc(args, ...)` 调用它了！
当你调用可调用对象时，angr 会在给定的地址设置一个 `call_state`，将给定的参数转储到内存中。然后基于这个 state 启动 `path_group`，直到所有路径都从函数中退出。将所有的结果状态合并到一起，将返回值从 state 中提取出来并返回

与 state 的所有交互都是通过 `SimCC` 来辅助完成的，参数在哪以及哪里获得返回值都是。默认情况下，在不同的架构中使用了一个合理的默认值。但如果想自定义，则可以在构建可调用对象时为 `SimCC` 对象传递参数 `cc` 

可以为函数参数传递符号数据，这是可以正常工作的。
甚至可以传递更为复杂的数据，比如字符串、列表、结构体，甚至是 Python 原生数据结构（元组作为结构体）。这些都可以轻松地序列化到 state 中。
如果你想指定一个指针到一定值，就可以在 `PointerWrapper` 对象上“装饰”它，例如 `b.factory.callable.PointerWrapper`。
对指针实现的装饰确实容易令人感到困惑，但是可以归结为“除非使用 PointerWrapper 或者特定的 SimArrayType 来指定、它们还未被包装在指针中、原始数据类型为字符串、数组或元组，否则指针中什么都不会被自动“装饰”，”

如果不关心调用的实际返回值，可以使用 `func.perform_call(arg, ...)`，属性 `func.result_state` 和 `func.result_path_group` 都会被填充。
即使正常调用一个可调用对象，这些属性也会被填充，但是这种情况下可能会更关心！
