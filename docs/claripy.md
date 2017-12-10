# 求解引擎

`angr` 的求解器被称作 `Claripy` ， `Claripy` 提供了如下功能：

- `Claripy ASTs` (`claripy.ast.Base` 的子类) 提供了一种与具体符号表达式交互的统一方式。
- `Claripy` 前端提供了一个在不同后端解决符号(包括约束求解)表达式的统一接口。

`Claripy` 在后端无缝协调多个不同的后端，具体的位向量， `VSA` 构造， `SAT` 求解器。

大多数 `angr` 用户都不需要直接与 `angr` 交互(除了代表符号表达式的 `claripy AST` 对象)，angr在内部处理大多数与Claripy的交互。然而，在处理表达式时，对 `angr` 的理解是有用的。

## Claripy ASTs

`Claripy AST` 抽象出 `Claripy` 支持的构造之间的差异。它们在基础数据类型上定义了一个操作数 (例如, `(a + b) / c)` ，`Claripy` 通过将请求分派到后端来处理这些操作在底层对象本身上的应用。

目前, `Claripy` 支持以下类型的语法树：

| 名字 | 描述        |  支持 (`Claripy` 后端)      | 示例代码      |
|------|-------------|-----------------------------|---------------|
| BV | 这是位向量，无论是符号还是具体值，都有一个大小（位）| BackendConcrete, BackendVSA, BackendZ3 | <ul><li>创建一个32位的符号位向量 `"x"` : `claripy.BVS('x', 32)`</li><li>创建一个值为 `0xc001b3475` 的 `32` 位向量: `claripy.BVV(0xc001b3a75, 32)`</li><li>创建一个 `32` 位 `"strided interval"` 可以被 `10` 整除的 `1000` 到 `2000` 之间的数（见 `VSA` 文档）: `claripy.SI(name='x', bits=32, lower_bound=1000, upper_bound=2000, stride=10)`</li></ul>   |
| FP | 这是一个浮点数，无论是符号还是具体的值 | BackendConcrete, BackendZ3 | TODO  |
| Bool | 这是布尔型操作数 (`True` 或者 `False`). | BackendConcrete, BackendVSA, BackendZ3 | `claripy.BoolV(True)`, 或者 `claripy.true` 或者 `claripy.false`, 或者两个 `ASTs` 的比较值(例如, `claripy.BVS('x', 32) < claripy.BVS('y', 32)` |

以上所有的创建代码都会返回 `claripy.AST` 对象，然后可以执行操作。 `ASTs` 提供了一些有用的操作。

```python
>>> import claripy

>>> bv = claripy.BVV(0x41424344, 32)

# Size - you can get the size of an AST with .size()
>>> assert bv.size() == 32

# Reversing - .reversed is the reversed version of the BVV
>>> assert bv.reversed is claripy.BVV(0x44434241, 32)
>>> assert bv.reversed.reversed is bv

# Depth - you can get the depth of the AST
>>> print bv.depth
>>> assert bv.depth == 1
>>> x = claripy.BVS('x', 32)
>>> assert (x+bv).depth == 2
>>> assert ((x+bv)/10).depth == 3
```

在 `AST` 上应用一个条件（==，！=等）将返回一个表示正在执行的条件的 `AST 。 例如：


```python
>>> r = bv == x
>>> assert isinstance(r, claripy.ast.Bool)

>>> p = bv == bv
>>> assert isinstance(p, claripy.ast.Bool)
>>> assert p.is_true()
```
你可以以不同的方式组合这些条件

```python
>>> q = claripy.And(claripy.Or(bv == x, bv * 2 == x, bv * 3 == x), x == 0)
>>> assert isinstance(p, claripy.ast.Bool)
```

当我们讨论 `Claripy` 的求解器的时候它的有用性就会显示出来，通常，`Claripy` 支持所有的正常的 `python` 操作(`+, -, |, ==,` 等)，并且通过 `Claripy` 提供额外的。以下是后者提供的可用操作列表。

| 名字 | 描述        | 例子    |
|------|-------------|---------|
| LShR | 逻辑上将一个位表达式(`BVV, BV, SI`)右移。 | `claripy.LShR(x, 10)` |
| SignExt | 符号位扩展 | `claripy.SignExt(32, x)` 或者 `x.sign_extend(32)` |
| ZeroExt | 零扩展 | `claripy.ZeroExt(32, x)` 或者 `x.zero_extend(32)` |
| Extract | 从一个位表达式提取给定的位| 提取 `x` 最右边的位 : `claripy.Extract(7, 0, x)` 或者 `x[7:0]` |
| Concat | 将几个位表达式连接到一个新的位表达式中 | `claripy.Concat(x, y, z)` |
| RotateLeft | 循环左移表达式 | `claripy.RotateLeft(x, 8)` |
| RotateRight | 循环右移表达式 | `claripy.RotateRight(x, 8)` |
| Reverse | 翻转 | `claripy.Reverse(x)` 或者 `x.reversed` |
| And | 逻辑与（布尔型） | `claripy.And(x == y, x > 0)` |
| Or | 逻辑或（布尔型） | `claripy.Or(x == y, y < 10)` |
| Not | 逻辑非（布尔型） | `claripy.Not(x == y)` is the same as `x != y` |
| If | If-then-else | 选择两个表达式中的最大值: `claripy.If(x > y, x, y)` |
| ULE | 无符号小于或等于 | 检查 `x` 是否小于等于 `y` : `claripy.ULE(x, y)` |
| ULT | 无符号小于 | 检查 `x` 是否小于 `y`: `claripy.ULT(x, y)` |
| UGE | 无符号大于或等于 | 检查 `x` 是否大于或等于 `y`: `claripy.UGE(x, y)` |
| UGT | 无符号大于 | 检查 `x` 是否大于 `y`: `claripy.UGT(x, y)` |
| SLE | 有符号小于等于 | 检查 `x` 是否小于等于 `y`: `claripy.SLE(x, y)` |
| SLT | 有符号小于 | 检查 `x` 是否小于 `y`: `claripy.SLT(x, y)` |
| SGE | 有符号大于等于 | 检查 `x` 是否大于等于 `y`: `claripy.SGE(x, y)` |
| SGT | 有符号大于| 检查 `x` 是否大于 `y`: `claripy.SGT(x, y)` |


**注意:** `python` 默认的 `>`, `<`, `>=`, 和 `<=` 在 `Claripy` 是无符号的. 这和在 `z3` 中是不同的，因为在二进制分析中这看起来更自然。

## Solvers

与 `Claripy` 交互的主要是 `Claripy` 求解器。求解器公开的 `API` 可以以不同方式解释 `ASTs` 并且返回可用的值。有几种不同的求解器。

| 名字 | 描述        |
|------|-------------|
| Solver | 类似于 `z3.Solver()`,跟踪符号变量的约束，并且使用约束求解器（现在是 `z3`）计算符号表达式。 |
| SolverVSA | 这个求解器使用 `VSA` 来推理值，它是一个近似求解器，产生的值没有执行实际的约束求解。 |
| SolverReplacement | 这个解析器充当子求解器的传递，允许动态地替换表达式。它被其他求解器用作辅助工具，可以直接用于实现奇异分析。 |
| SolverHybrid | 这个求解器结合了 `SolverReplacement` 和求解器（`VSA` 和 `Z3`），允许近似值。你可以指定你的计算是否需要一个准确的结果，求解器会帮助你完成余下的任务|
| SolverComposite | 这个求解器实现了在较小的约束条件下实现优化以加速求解|

一些使用求解器的例子:

```python
# create the solver and an expression
>>> s = claripy.Solver()
>>> x = claripy.BVS('x', 8)

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

自定义求解器可以通过组合一个明确的前端（处理与 `SMT` 求解器或底层数据域的实际交互的类）和前端的一些混合(处理类似缓存、过滤重复约束、进行机会化简化等)的组合而构建。

## Claripy 后端

后端是 `Claripy` 进行计算的主力。
`Claripy` 向外公开了 `ASTs`，但是当实际的计算必须完成时，它将这些 `ASTs` 推到可以由后端自己处理的对象中。
这为外面提供了一个统一的接口，并且支持不同类型的计算。
例如，`BackendConcrete` 为具体的位向量和布尔型提供了计算支持，`BackendVSA` 引入了诸如 `StridedIntervals` 的 `VSA` 结构，并且详细描述了操作时发生的细节，`BackendZ3` 提供了对符号变量和约束解决的支持。

有一组函数需要后端去实现。对于所有这些函数，对于所有这些功能，“公共”版本预计能够处理 `claripy` 的 `AST` 对象，而“私有”版本只能处理特定于后端本身的对象。
这是因 `Python` 语法区分的:公共函数将命名为func()，而私有函数将是_func()。
所有函数都应该返回可由后端应用于其私有方法的对象。如果不能这样做(也就是，有些功能正在尝试后端无法处理)，后端应该增加一个 `BackendError`。
在这种情况下，`Claripy` 将在它的列表中移动到下一个后端。

所有的后端都必须实现一个 `"convert()"` 函数。这个函数接收一个 `claripy AST` ，并应该返回后端可以用它的私有方法处理的一个对象。
后端还应该实现一个 `_convert()` 方法，可以接收任何不是一个准确的 `AST` 对象（例如一个整数或来自不同后端的对象）。
如果 `convert()` 或者 `_convert()` 接收到无法转换为在后端可以使用的格式的数据，后端应该调用 `BackendError` ，因此该对象不会被使用。
所有的后端都必须实现基础“后端”抽象类的任何功能，这些类目前都是 `"NotImplementedError()"`。

`Claripy` 与后端的合约如下：后端应该能够处理它们在私有函数中返回的任何对象，它们从它们的私有或公共函数返回。
`Claripy` 将永远不会将对象传递给任何后端私有函数，这些后端私有函数不是作为该后端的私有或公共函数的返回值。
一个例外是`convert（）`和`_convert（）`，因为 `Claripy` 会尝试在 `_convert()` 中处理任何输入的数据，以查看后端是否可以处理该类型的对象。

### 模型对象

为了在 `ASTs` 中执行实际的、有用的计算，`Claripy` 使用模型对象。模型对象是由 `AST` 表示的操作的结果。`Claripy` 期望这些对象从后端返回，并将这些对象传递到后端的其他函数。

