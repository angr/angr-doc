# 符号表达与约束求解

`angr` 的强大并不是因为它是一个仿真器，而是能够执行我们所说的符号变量。变量拥有一个符号，而不是一个具体的值，实际上只是一个名字。在使用该变量进行算数运算时将产生一个操作树（从编译器理论可以称为抽象语法树或 `AST` ）。为了提出类似于"给定操作序列的输出，那输入必须是什么？"的问题，可以将 `AST` 转换为类似于 `z3` 的 `SMT` 求解器的约束

## Bitvectors使用

让我们使用样本 `project` 和 `state` 来开始数字之旅

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```

`bitvector` 只是用有界整数的语义来解释的一个比特序列，下面是一些例子

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

正如您看到的，您可以拥有一个任意位的比特序列，称之为 `bitvector`。您也可以使用它们做算数运算：

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

不过 `one + weird_nine` 是不正确的。
不同长度的 `bitvector` 进行运算时会发生类型错误。
但是您可以通过扩张 `weird_nine` 使其具有合适的位数:

```python
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>
```

`zero_extend` 将会在 `bitvector` 左边填充适当位数的 `0` 。
您还可以使用 `sign_extend` 来填充， `bitvector` 符号位的值将会在左边被填充。

现在我们来混合介绍一些符号。

```python
# Create a bitvector symbol named "x" of length 64 bits
>>> x = state.solver.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = state.solver.BVS("y", 64)
>>> y
<BV64 y_10_64>
```

`x` 和 `y` 现在是一个_符号变量_，有点像七年级代数中学习的变量。请注意，您提供的名称因为追加了一个递增计数器而损坏，您可以根据需要对他们进行尽可能多的算数运算，但是您不会得到一个数字，而是一个 `AST`。

```python
>>> x + one
<BV64 x_9_64 + 0x1>

>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>

>>> x - y
<BV64 x_9_64 - y_10_64>
```

从技术上来说 `x` 和 `y` 甚至 `one` 都是 `ASTs` - 任何 `bitvector` 都是一个操作树，即使这个操作树只有一层。
为了理解这一点，让我们来学习下如何处理 `ASTs`。

每个 `AST` 都有一个 `.op` 和 `.args`。
`op` 是正在执行的操作的名字的字符串表示，`args` 是执行操作时作为输入的值。除非 `op` 是 `"BVV"` 或 `"BVS"` (或者其他几个)，`args` 都是其他的 `ASTs`，操作树将会在 `BVVs` 或 `BVSs` 终止。

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

从这里开始，我们将使用 `bitvector` 这个词来指代任何一个最顶端的操作产生一个 `bitvector` 的 `AST`。
也可以使用 `AST` 来表示其他数据类型，包括浮点数，以及我们即将看到的布尔值。

## 符号约束

在任何两个类型相似的 `AST` 之间进行比较操作会产生另一个 `AST` - 而不是一个 `bitvector`,而是一个符号表达的布尔类型的值。

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

默认情况下比较是无符号的。
在最后一个例子中 `-5` 被转换为了 `<BV64 0xfffffffffffffffb>` ,肯定不会小于 `100`。
您如果想进行有符号之间的比较，可以通过使用 `one_hundred.SGT(-5)` 在本章末尾可以找到完整的操作列表。

这段代码也说明了在使用 `angr` 的重要一点，您不应该直接在 `if` 或 `while` 语句的条件下进行变量的比较，因为不会得到一个确定的值。

即使有一个确定的值，`if one > one_hundred` 也会引起异常。
相反，你应该使用 `solver.is_true` 和 `solver.is_false`,可以在不执行约束求解的时候测试真假。

```python
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> state.solver.is_true(yes)
True
>>> state.solver.is_false(yes)
False
>>> state.solver.is_true(no)
False
>>> state.solver.is_false(no)
True
>>> state.solver.is_true(maybe)
False
>>> state.solver.is_false(maybe)
False
```

## 约束求解

您可以通过使用任何符号布尔值作为符号变量有效值的断言，并将其作为_约束_添加到对应的 `state` 。
然后您可以通过符号表达式的求值来产生一个具体的值。

一个例子可能比这里的解释更清楚：
```python
>>> state.solver.add(x > y)
>>> state.solver.add(y > 2)
>>> state.solver.add(10 > x)
>>> state.solver.eval(x)
4
```

通过将这些约束添加到 `state` ，我们迫使约束求解器将它们视为必须满足其返回值的断言。
如果您运行这些代码，你可能会得到一个不同于 `x` 的值，但是这个值肯定大于3（因为 `y` 必须大于 `2`，而 `x` 必须大于 `y` ）,小于 `10`。
此外，如果你输入  `state.solver.eval(y)`，您得到的 `y` 值和 `x` 值是一致的。
如果在两次查询之间没有添加任何约束，那么结果将是一致的。

从这里开始，我们将看到如何完成在本章开头提到的任务 - 找到产生给定输出的输入值。

```python
# get a fresh state without constraints
>>> state = proj.factory.entry_state()
>>> input = state.solver.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381
```

请注意，这个方法只适用于在 `bitvector` 语义。
如果我们在整数域上运行，将会无解。

如果我们添加冲突或矛盾的约束，使得没有可以使约束得到满足的变量的值分配， `state` 变为不满足的，查询时将会产生异常。
您可以使用 `state.satisfiable()` 来检查一个 `state` 的可满足性。

```python
>>> state.solver.add(input < 2**32)
>>> state.satisfiable()
False
```

您也可以计算更复杂的表达式，而不仅仅是单个变量。

```python
# fresh state
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

由此我们可以看到 `eval` 是将任何 `bitvector` 转化为 `python` 原语，同时又保持 `state` 完整性的一种通用方法。
这也是为什么我们是有 `eval` 将具体的 `bitvector` 转化为 `python` 整形的原因。

还要注意的是尽管变量 `x` 和 `y` 在旧 `state` 创建，但仍可以在新 `state` 使用。
变量不与任何一个 `state` 绑定，可以自由存在。

## 浮点数

`z3` 已经支持 `IEEE754` 标准，所以 `angr` 也可以使用它们。
主要的区别不是宽度，而是一个浮点数有一个排序。
您可以使用 `FPV` 和 `FPS` 来创建符号变量和具体的值。 

```python
# fresh state
>>> state = proj.factory.entry_state()
>>> a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)
>>> a
<FP64 FPV(3.2, DOUBLE)>

>>> b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)
>>> b
<FP64 FPS('FP_b_0_64', DOUBLE)>

>>> a + b
<FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>

>>> a + 4.4
<FP64 FPV(7.6000000000000005, DOUBLE)>

>>> b + 2 < 0
<Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>
```

有一点需要在这里说明 - 对于初学者来说，在浮点数上使用预印版并不太好。
但在过去，大多数操作都有一个第三操作数，在使用二进制运算符时隐式地添加 - 舍入模式。
`IEEE754` 支持多种舍入模式(圆到近，整数到零，圆到整等等)，所以 `z3` 也支持它们。
如果您想指定一个操作的舍入模式，请指明 `fp` 的操作（例如：`solver.fpAdd`）,并且使用一个舍入模式( `solver.fp.RM_*` 里面的一个) 作为第一个参数。

约束和求解原理相同，使用 `eval` 会返回一个浮点数:

```python
>>> state.solver.add(b + 2 < 0)
>>> state.solver.add(b + 2 > -1)
>>> state.solver.eval(b)
-2.4999999999999996
```

这很好，但有时候我们需要直接使用用 `bitvector` 表示的浮点数。
你可以将 `bitvector` 解释为浮点数，反之亦然，使用 `raw_to_bv` 和 `raw_to_fp`：

```python
>>> a.raw_to_bv()
<BV64 0x400999999999999a>
>>> b.raw_to_bv()
<BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>

>>> state.solver.BVV(0, 64).raw_to_fp()
<FP64 FPV(0.0, DOUBLE)>
>>> state.solver.BVS('x', 64).raw_to_fp()
<FP64 fpToFP(x_1_64, DOUBLE)>
```

这些转换保留了位模式，就像您将一个浮点数转化为一个整型指针，反之亦然。
但是，如果您想尽可能的保留原值，就像将浮点类型转换为整型（反之亦然），则可以使用另一组方法，`val_to_fp` 和 `val_to_bv`。
这些方法因为浮点数的性质必须使用目标值的大小或类型作为参数 

```python
>>> a
<FP64 FPV(3.2, DOUBLE)>
>>> a.val_to_bv(12)
<BV12 0x3>
>>> a.val_to_bv(12).val_to_fp(state.solver.fp.FSORT_FLOAT)
<FP32 FPV(3.0, FLOAT)>
```

这些方法也可以使用 `signed` 作为参数，指定源参数和目标参数的符号。

## 其他方法

`eval` 将会给你的表达式一个可能的解决方案，但是如果你想得到多个呢？
如果你想确保解决方案是唯一的呢？
求解器提供了几种常见的求解模式:

- `solver.eval(expression)` 对给定的表达式提供一个解决方案
- `solver.eval_one(expression)` 对给定的表达式提供一个解决方案，如果大于一个则会抛出异常。
- `solver.eval_upto(expression, n)` 对给定的表达式提供 `n` 种解决方案，如果少于 `n` ,则返回小于 `n` 。
- `solver.eval_atleast(expression, n)` 对给定的表达式提供 `n` 种解决方案，如果少于 `n` ，则会抛出错误。
- `solver.eval_exact(expression, n)` 对给定的表达式提供 `n` 中解决方案，多于或者少于都会抛出错误。
- `solver.min(expression)` 对给定的表达式提供最小可能的解决方案。
- `solver.max(expression)` 对给定的表达式提供最大可能的解决方案。

此外，所有这些方法都可以使用以下关键字参数：

- `extra_constraints` 可以作为约束条件的元组传递，这些约束将会在求解是被考虑，但是不会被增加到 `state`。
- `cast_to` 可以将结果转换成某一数据类型。
现在只能是 `str` 类型，这将会返回底层数据的字节表示。
例如： `state.solver.eval(state.solver.BVV(0x41424344, 32), cast_to=str)` 将返回 `"ABCD"`。
  
## 总结

在读完本章后，您应该能创建和操作 `bitvector`,布尔值和浮点值来形成操作数，然后在一组约束条件下求解某一个 `state`。
希望通过这一点您可以了解到使用 `ASTs` 表示计算和约束求解器的强大。

[附录](appendices/options.md), 你可以找到应用于 `ASTs` 的其他操作的引用。
