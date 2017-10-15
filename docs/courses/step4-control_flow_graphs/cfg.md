# angr courses - step 4 - control flow graphs

The binary for this course can be found [here](./).

## 背景：控制流图
控制流图表示程序所有可能的路径。其节点是基本块，节点间用有向边连接表示在二进制程序中存在基本块 _a_ 到基本块 _b_ 的跳转。
因为 CFG 可以很好地理解程序的功能，故而在二进制分析中扮演着关键角色
在 angr 中也被用于其他分析中，并且实现了两次。一个主要侧重准确性（CFGAccurate），另一个主要侧重速度（CFGFast）

我们使用 angr 的 CFGAccurate 来从给定的二进制程序中生成一个控制流图，该程序要求特定个用户输入
由于 angr 本身不能显示 CFG（例如以 PNG 图片格式），我们使用了 [angrutils](https://github.com/axt/angr-utils) 的函数 plot_cfg
CFGAccurate 的多个参数在 [文档](/docs/analyses/cfg_accurate.md) 和 [API](http://angr.io/api-doc/angr.html#angr.analyses.cfg_accurate.CFGAccurate) 中有着详细的阐述


```python
# 导入 angr 与 angrutils 的 plot_cfg
>>> import angr
>>> from angrutils import plot_cfg

# 装载二进制程序到 project
# 我们不想分析外部库，所以不加载这些外部库，angr 会替换它们
>>> proj = angr.Project("docs/courses/step4-control_flow_graphs/step4.bin", load_options={'auto_load_libs': False})

# 查找主函数地址
# 设置为生成 CFG 的起始点
>>> main_addr = proj.loader.main_bin.get_symbol("main").addr

# 生成 CFG
>>> cfg = proj.analyses.CFGAccurate(fail_fast=True, starts=[main_addr], context_sensitivity_level=4, keep_state=True, call_depth=10, normalize=True)

# 渲染生成的 CFG 为 PNG 图片
>>> plot_cfg(cfg, "step4_cfg_main", asminst=True, vexinst=False, func_addr={main_addr: True}, debug_info=False, remove_imports=True, remove_path_terminator=True)
```

生成的 CFG 如下，可以看出这个二进制程序：
1. 打印输出（调用 puts）
2. 获取用户输入（调用 fgets）
3. 对输入进行 base64 解码（调用 b64d）
4. 进行一些数学运算
5. 将运算结果和一些硬编码的值进行检查比较
6. 打印提示信息（调用 puts）

![CFG not found][cfg]

[cfg]: ./step4_cfg_main.png "CFGAccurate"