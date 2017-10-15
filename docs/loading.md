# 装载二进制程序 - CLE 和 angr Projects

先前，您对 angr 的装载能力只是浅尝辄止 - 您装载了 `/bin/true`，,并且不使用共享库又装载了一次。`proj.loader` 与其能做的事儿也略有展现。现在，我们将介绍这些接口的细微差别，以及这些接口可以提供哪些信息

我们简要的介绍了 angr 的二进制装载组件 CLE。CLE 代表着 "CLE Loads Everything"，主要负责装载一个二进制文件 \(与其依赖的任意库\) 并以易于使用的方式传递给其他 angr 组件

## 装载器

我们重新装载 `/bin/true` 并且深入了解如何和装载器进行交互

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> proj.loader
<Loaded true, maps [0x400000:0x5008000]>
```

### 装载对象

CLE 装载器 \(`cle.Loader`\) 表示加载的 _binary objects_ 的整个集合，装载并映射到单个内存空间。
每个二进制对象都由装载器后端装载，该后端可以根据其类型进行处理 \(`cle.Backend` 的一个子类\)。例如 `cle.ELF` 被用于装载 ELF 二进制程序

内存中也存在着不与任何装载的二进制程序对应的对象，例如，用于提供线程本地存储的对象、用于提供未解析符号的外部对象

使用 `loader.all_objects` 可以获得 CLE 装载对象的完整列表，以及几个更有针对性的分类：

```python
# 所有装载对象
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>,
 <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>,
 <ELFTLSObject Object cle##tls, maps [0x3000000:0x300d010]>,
 <KernelObject Object cle##kernel, maps [0x4000000:0x4008000]>,
 <ExternObject Object cle##externs, maps [0x5000000:0x5008000]>

# This is the "main" object, the one that you directly specified when loading the project
>>> proj.loader.main_object
<ELF Object true, maps [0x400000:0x60105f]>

# 从共享对象名字到对象的字典映射
>>> proj.loader.shared_objects
{ 'libc.so.6': <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>
  'ld-linux-x86-64.so.2': <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>}

# 这是从 ELF 文件装载的所有对象
# 如果这是一个 Windows 程序，我们将使用 all_pe_objects！
>>> proj.loader.all_elf_objects
[<ELF Object true, maps [0x400000:0x60105f]>,
 <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>,
 <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>]
 
# 这是“外部对象”，我们用它来提供未解析的 import 的地址与 angr 内部对象
>>> proj.loader.extern_object
<ExternObject Object cle##externs, maps [0x5000000:0x5008000]>

# 该对象用来为仿真的系统调用提供地址
>>> proj.loader.kernel_object
<KernelObject Object cle##kernel, maps [0x4000000:0x4008000]>

# 最后，我们可以得到给定地址对象的引用
>>> proj.loader.find_object_containing(0x400000)
<ELF Object true, maps [0x400000:0x60105f]>
```

您可以直接和这些对象进行交互，从中提取元数据：

```python
>>> obj = proj.loader.main_object

# 对象的入口点
>>> obj.entry
0x400580

>>> obj.min_addr, obj.max_addr
(0x400000, 0x60105f)

# 检索 ELF 的 segment 和 section 
>>> obj.segments
<Regions: [<ELFSegment offset=0x0, flags=0x5, filesize=0xa74, vaddr=0x400000, memsize=0xa74>,
           <ELFSegment offset=0xe28, flags=0x6, filesize=0x228, vaddr=0x600e28, memsize=0x238>]>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
           <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
           <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
            ...etc
            
# 可以通过一个给定的地址得到一个单独的 segment 或 section
>>> obj.find_segment_containing(obj.entry)
<ELFSegment offset=0x0, flags=0x5, filesize=0xa74, vaddr=0x400000, memsize=0xa74>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>

# Get the address of the PLT stub for a symbol
>>> addr = obj.plt['__libc_start_main']
>>> addr
0x400540
>>> obj.reverse_plt[addr]
'__libc_start_main'

# Show the prelinked base of the object and the location it was actually mapped into memory by CLE
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000
```

### 符号与重定向

您也可以在使用 CLE 时使用符号，符号是可执行格式世界中的基本概念，可以有效地将 name 映射到地址

从 CLE 获取符号最简单的方法就是 `loader.find_symbol`，给它一个 name 或地址可以返回一个 Symbol 对象

```python
>>> malloc = proj.loader.find_symbol('malloc')
>>> malloc
<Symbol "malloc" in libc.so.6 at 0x1054400>
```

符号中最有用的属性就是其 name、owner 和地址，但符号的地址可能是不确定的。
有三种方式得到 Symbol 对象的地址：

- `.rebased_addr` 是其在全局地址空间的地址，也是输出的默认值
- `.linked_addr` 是其相对于二进制文件预链接基址的地址，例如 `readelf(1)`
- `.relative_addr` 是其相对于对象库基址的地址，特别是在 Windows 系统中叫做 RVA（相对虚拟地址）

```python
>>> malloc.name
'malloc'

>>> malloc.owner_obj
<ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>

>>> malloc.rebased_addr
0x1054400
>>> malloc.linked_addr
0x54400
>>> malloc.relative_addr
0x54400
```

除了提供调试信息外，symbol 还支持动态链接。libc 将 malloc symbol 作为 export，主要的二进制程序都依赖它
如果我们要求 CLE 直接从主对象给我们一个 malloc symbol，它会告诉我们这是一个 _import symbol_。
导入符号没有明确意义上的地址，但是确实提供了用于解析它们的符号的引用 `.resolvedby`

```python
>>> malloc.is_export
True
>>> malloc.is_import
False

# On Loader, the method is find_symbol because it performs a search operation to find the symbol.
# On an individual object, the method is get_symbol because there can only be one symbol with a given name.
>>> main_malloc = proj.loader.main_object.get_symbol("malloc")
>>> main_malloc
<Symbol "malloc" in true (import)>
>>> main_malloc.is_export
False
>>> main_malloc.is_import
True
>>> main_malloc.resolvedby
<Symbol "malloc" in libc.so.6 at 0x1054400>
```

import 和 export 之间的连接关系应该在内存中注册，这种具体的方式由拎一个成为 _重定向_ 的概念来处理
重定向的意思是说：当您用一个 export symbol 匹配到一个 import 时，请将 export 的地址写入 _\[location\]_，格式为 _\[format\]_
我们可以使用 `obj.relocs` 看到一个对象（`Relocation` 实例）的重定向清单，或者只映射 symbol name 到 Relocation 上作为 `obj.imports`
这里没有 export symbol 的相应清单

重定向对应的 import symbol 可以作为 `.symbol` 被访问
重定向将要写入的地址是可以通过任意可以用于 Symbol 的地址识别符进行访问，还可以用 `.owner_obj` 得到重定向的对象的引用

```python
# 重定向不会有良好的格式，所以这些地址是 Python 内部的，和我们的程序无关
>>> proj.loader.shared_objects['libc.so.6'].imports
{u'__libc_enable_secure': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4221fb0>,
 u'__tls_get_addr': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x425d150>,
 u'_dl_argv': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4254d90>,
 u'_dl_find_dso_for_object': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x425d130>,
 u'_dl_starting_up': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x42548d0>,
 u'_rtld_global': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4221e70>,
 u'_rtld_global_ro': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4254210>}
```

如果一个 import 不能解析为任何一个 export。例如，无法找到共享库，CLE 将会自动更新外部对象 (`loader.extern_obj`) 来声明它将识别该 symbol 为一个 export

## 装载选项

如果您正在使用 `angr.Project` 装载某些程序，并且想要为 Project 隐式创建的 `cle.Loader` 实例传递一些选项，您可以直接将关键字参数传递给 Project 的构造函数，通过它传递给 CLE。
如果您想知道所有可能的选项参数，您应该查看 CLE 的 [API 文档](http://angr.io/api-doc/cle.html)
我们现在只会介绍一些重要且常用的选项

#### 基本选项

我们已经讨论过 `auto_load_libs` - 它可以启用/禁用 CLE 自动尝试解析共享库依赖，默认是开启的。
此外，如果 `except_missing_libs` 被设置为 true，在二进制文件具有无法解析的共享库依赖时抛出异常

您可以传递一个字符串列表给 `force_load_libs`，列表中的任何东西都会被认为是未解析的共享库依赖，或者可以传递字符串列表给 `skip_libs` 来阻止这些名称的库被解析为依赖关系。
此外，您可以传递字符串列表给 `custom_ld_path`，将会将其作为共享库搜索的附加路径放在所有默认路径之前，被装载程序目录、当前工作目录与系统库目录

#### 特定二进制选项

CLE 也可以指定一些仅适用于特定二进制对象的选项，参数 `main_ops` 和 `lib_opts` 通过选项字典来实现这一功能。
`main_opts` 提供从选项名到选项值的映射，`lib_opts` 提供库名到前一个字典的映射，该字典提供从选项名到选项值的映射

每个后端对应的选项不同，但是有一些是通用的：

* `backend` - 使用的后端，作为一个类或者一个名字
* `custom_base_addr` - 使用的基地址
* `custom_entry_point` - 使用的入口点
* `custom_arch` - 使用的架构

例如:

```python
angr.Project(main_opts={'backend': 'ida', 'custom_arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
```

### 后端

CLE 目前拥有用于静态装载 ELF, PE, CGC, Mach-O 与 ELF core dump 文件的后端，其功能与使用 IDA 装载、将文件装载到 flat 地址空间相同。CLE 会自动检测并匹配正确的后端来使用，所以不需要手动指定

当然，也可以在选项中强制指定 CLE 使用某一个后端来进行装载，某些后端无法自动检测需要使用的架构，_必须_ 使用 `custom_arch` 手动指定。如果和任何一个架构都不匹配，angr 会确定您所指定的架构，其几乎可以为任何受支持的架构提供任意通用标识符

要引用后端，请使用下表中的名字：

| 后端名称 | 描述 | 需要 `custom_arch`? |
| --- | --- | --- |
| elf | 基于 PyELFTools 的 ELF 文件静态装载器 | no |
| pe | 基于 PEFile 的 PE 文件静态装载器 | no |
| mach-o | Mach-O 文件的静态装载器，不支持动态链接或 rebasing | no |
| cgc | CGC 二进制程序静态装载器 | no |
| backedcgc | 允许指定内存和寄存器的 CGC 静态装载器 | no |
| elfcore | ELF core dumps 的静态装载器 | no |
| ida | 启动一个 IDA 实例来解析这个文件 | yes |
| blob | 以 flat image 加载该文件进入内存 | yes |

## 符号化函数摘要 Symbolic Function Summaries

默认情况下， Project 试着通过称为 _SimProcedures_ 的符号化摘要来替换对库函数的外部调用 - 实际上是用 Python 模拟库函数对 state 的影响
我们已经实现了 SimProcedures 中的 [一系列功能](https://github.com/angr/angr/tree/master/angr/procedures) ，这些内置的功能更可以在字典 `angr.SIM_PROCEDURES` 中得到，该字典是双层的，第一层的键是包名 \(libc, posix, win32, stubs\)，第二层的键是库函数的名字。执行 SimProcedure 代替从系统装载的实际库函数开始分析更易于处理，当然是以 [一些潜在的不准确](/docs/gotchas.md) 作为代价。

当给定的函数没有此类摘要时：

* 如果 `auto_load_libs` 是 `True` \(这也是默认值\)，则会执行真正的库函数。这取决于具体的功能，例如一些 libc 的函数的分析非常复杂，很可能因为试着执行导致路径状态数量爆炸
* 如果 `auto_load_libs` 是 `False`，则外部函数无法解析，Project 将会解析它们到一个通用的、被叫做 `ReturnUnconstrained` 的 "stub" SimProcedure 上。它会在每次被调用时返回唯一的无约束符号化值
* 如果 `use_sim_procedures` \(这个参数是 `angr.Project` 的，不是 `cle.Loader` 的\) 是 `False` \(默认为 `True`\)，则只有外部对象提供的符号被 SimProcedures 替换，并且它们会被 stub `ReturnUnconstrained` 替换，它不会执行任何操作只返回一个符号化值
* 通过将参数 `exclude_sim_procedures_list` 和 `exclude_sim_procedures_func` 送给 `angr.Project` 可以指定特定的符号排除在 SimProcedures 替换的范围之外
* 可以查看 `angr.Project._register_object` 的代码来确定具体的算法

#### Hooking

angr 用 Python 摘要代替库函数的机制叫做 Hooking。执行仿真时，每一步 angr 都会检查当前地址是否被 Hook，如果成功则在在地址运行 Hook 代码而不是二进制代码。
Hooking 的函数是 `proj.hook(addr, hook)`，Hook 的位置是一个 SimProcedure 实例。您可以通过 `.is_hooked`、`.unhook` 和 `.hooked_by` 来管理您工程中的钩子

Hooking 一个地址还有一个可替代的 API，通过使用 `proj.hook(addr)` 作为函数装饰器，可以自己指定 off-the-cuff 函数用作钩子。还可以选择指定一个 `length` 参数来确定钩子执行完成后向前跳转一些字节

```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.unhook(0x10000)
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```

此外，我们可以使用 `proj.hook_symbol(name, hook)` 作为第一个参数提供 symbol 的名字，来勾住 symbol 所在的地址。一个非常重要的用途就是用来扩展 angr 内建库 SimProcedures 的行为
由于这些库函数只是类，您可以进行子类化，覆写他们的函数，然后在 Hook 中使用您的子类

## So far so good!

到目前为止，您应该对 CLE 装载器和 angr Project 各级如何控制您分析环境中的各种使用方法有所了解了。还应该了解了 angr 通过 SimProcedures 挂钩复杂函数库提供函数摘要来简化分析。

为了查看 CLE 装载器中所有可用的信息以及后端的内容，请查看 [CLE API 文档](http://angr.io/api-doc/cle.html)
