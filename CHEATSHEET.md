# 介绍

本节旨在提供一个 angr 能做什么的概览，作为使用者的快速参考，不需要深入了解文档就可以学会一些用法

警告：该页面面向 angr 6，某些部分不适用于 angr 7

## 通用开始

一些有用的 imports

```python
import angr # 主框架
import claripy # 求解引擎
```

装载二进制程序

```python
proj = angr.Project("/path/to/binary", load_options={'auto_load_libs': False} ) # auto_load_libs 设置为 False 可以提高性能表现
```

## Path Groups

生成路径组对象

```python
path_group = proj.factory.path_group(state, threads=4)
```

## 探索分析路径组

选择不同的探索策略

```python
path_group.use_technique(angr.exploration_techniques.DFS())
```

直到一个路径组在 `find=` 的位置被发现，否则一直探索路径组

```python
avoid_addr = [0x400c06, 0x400bc7]
find_addr = 0x400c10d
path_group.explore(find=find_addr, avoid=avoid_addr)
```

```python
found = path_group.found[] # The list of paths that reached find condition from explore
found.state.se.any_str(sym_arg) # Return a concrete string value for the sym arg to reach this state
```

直到 lambda 表达式为 `True`，否则不停止探索路径组

```python
path_group.step(until=lambda p: p.active[0].addr >= first_jmp)
```

访问当前 STOUT 或 STDERR 是特别有用的（1 是 STDOUT 的文件描述符）

```python
path_group.explore(find=lambda p: "correct" in p.state.posix.dumps(1))
```

大搜索内存管理（自动丢弃 Stashes）

```python
path_group.explore(find=find_addr, avoid=avoid_addr, step_func=lambda lpg: lpg.drop(stash='avoid'))
```

### 手动探索

```python
path_group.step(step_func=step_func, until=lambda lpg: len(lpg.found) > 0)

def step_func(lpg):
    lpg.stash(filter_func=lambda path: path.addr == 0x400c06, from_stash='active', to_stash='avoid')
    lpg.stash(filter_func=lambda path: path.addr == 0x400bc7, from_stash='active', to_stash='avoid')
    lpg.stash(filter_func=lambda path: path.addr == 0x400c10, from_stash='active', to_stash='found')
    return lpg
```

启用日志记录：

```python
angr.path_group.l.setLevel("DEBUG")
```

### Stashes

移动 Stash：

```python
path_group.stash(from_stash="found", to_stash="active")
```

丢弃 Stashes：

```python
path_group.drop(stash="avoid")
```

## 约束求解器

创建一个符号化对象

```python
sym_arg_size = 15 #Length in Bytes because we will multiply with 8 later
sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)
```

将 sym_arg 限制在典型的 char 范围

```python
for byte in sym_arg.chop(8):
    initial_state.add_constraints(byte != '\x00') # null
    initial_state.add_constraints(byte >= ' ') # '\x20'
    initial_state.add_constraints(byte <= '~') # '\x7e'
```

使用参数来创建一个 state：

```python
argv = [project.filename]
argv.append(sym_arg)
state = project.factory.entry_state(args=argv)
```

使用参数来求解：

```python
argv1 = angr.claripy.BVS("argv1", flag_size * 8)
initial_state = b.factory.full_init_state(args=["./antidebug", argv1], add_options=simuvex.o.unicorn, remove_options={simuvex.o.LAZY_SOLVES})
```

## FFI 与 Hooking

在 ipython 中调用函数

```python
f = proj.factory.callable(adress)
f(10)
x=claripy.BVS('x', 64)
f(x) #TODO: Find out how to make that result readable
```

如果你感兴趣的内容没有直接返回，可能是因为：
例如，函数返回指向缓冲区的指针，仍然可以在函数返回后访问该 state


```python
>>> f.result_state
<SimState @ 0x1000550>
```

Hooking

```python
hook(addr, hook, length=0, kwargs=None)
```

已有用于 libc.so.6  函数的预定义钩子（对静态编译库有用）

```python
hook = simuvex.SimProcedures['libc.so.6']['atoi']
hook(addr, hook, length=4, kwargs=None)
```

使用 Simprocedure 进行 Hooking：

```python
class fixpid(SimProcedure):
    def run(self):
            return 0x30

b.hook(0x4008cd, fixpid, length=5)
```

## 其他有用的技巧

Drop into an ipython if a ctr+c is recieved (调试正在运行的脚本很有用)

```python
import signal
def killmyself():
    os.system('kill %d' % os.getpid())
def sigint_handler(signum, frame):
    print 'Stopping Execution for Debug. If you want to kill the programm issue: killmyself()'
    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)
```

得到路径组的调用跟踪，以发现我们 stuck 的位置

```python
path = path_group.active[0]
path.callstack_backtrace
```

获取基本块

```python
block = proj.factory.block(address)
block.capstone.pp() #Capstone object has pretty print and other data about the dissassembly
block.vex.pp()      #Print vex representation
```

## State 操纵

写入 state:

```python
aaaa = claripy.BVV(0x41414141, 32) # 32 = Bits
state.memory.store(0x6021f2, aaaa)
```

Read Pointer to Pointer from Frame:

```python
poi1 = new_state.se.any_int(new_state.regs.rbp)-0x10
poi1 = new_state.se.any_int(new_state.memory.load(poi1, 8, endness='Iend_LE'))
poi1 += 0x8
ptr1 = (new_state.se.any_int(new_state.memory.load(poi1, 8, endness='Iend_LE')))
```

从 State 中读取：

```python
key = []
for i in range(38):
    key.append(extractkey.se.any_int(extractkey.memory.load(0x602140+(i*4), 4, endness='Iend_LE')))
```

## 调试 angr

在每次内存读/写设置断点：

```python
new_state.inspect.b('mem_read', when=simuvex.BP_AFTER, action=debug_funcRead)
def debug_funcRead(state):
    print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address
```

在特定内存位置上设定断点：

```python
new_state.inspect.b('mem_write', mem_write_address=0x6021f1, when=simuvex.BP_AFTER, action=debug_funcWrite)
```
