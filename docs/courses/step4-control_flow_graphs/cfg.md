# angr courses - step 4 - control flow graphs

The binary for this course can be found [here](./).

##### Background: Control Flow Graphs
The control flow graph (CFG) represents all possible paths of a program.
Its nodes are the basic blocks and a directed edge from node _a_ to _b_ indicates that, in the binary, a jump exists from block _a_ to _b_.
The CFG plays a central role in binary analysis, as it gives a good understanding of what a program does.
In angr, it is used in several other analyses and is implemented twice, with the goal being on the one hand accuracy (CFGAccurate) and on the other hand speed (CFGFast).


We are using angr's CFGAccurate to generate a CFG from the given binary which asks for a specific user input.
As angr itself cannot display CFGs (e.g. as png-files), we are using [angrutils'](https://github.com/axt/angr-utils) function plot_cfg.
The various parameters of CFGAccurate are described in the [docs](/docs/analyses/cfg_accurate.md) and in the [api](http://angr.io/api-doc/angr.html#angr.analyses.cfg_accurate.CFGAccurate).


```python
# Import both angr and angrutils' plot_cfg
>>> import angr
>>> from angrutils import plot_cfg

# Load the binary into the project
# We don't want external libraries to be analyzed so dont load them, they will be replaced by angr
>>> proj = angr.Project("docs/courses/step4-control_flow_graphs/step4.bin", load_options={'auto_load_libs': False})

# Find the address of the main function
# It will be used as a starting point for the generation of the CFG
>>> main_addr = proj.loader.main_bin.get_symbol("main").addr

# Generate the CFG
>>> cfg = proj.analyses.CFGAccurate(fail_fast=True, starts=[main_addr], context_sensitivity_level=4, keep_state=True, call_depth=10, normalize=True)

# Render the generated CFG as a png image
>>> plot_cfg(cfg, "step4_cfg_main", asminst=True, vexinst=False, func_addr={main_addr: True}, debug_info=False, remove_imports=True, remove_path_terminator=True)
```

The generated CFG is displayed below.
It can be seen that this binary
1. prints something (call to puts)
2. gets user input (call to fgets)
3. base64-Decodes that input (call to b64d)
4. performs some math operations on it
5. checks the result against some hardcoded values
6. prints some win/fail messages (calls to puts)

![CFG not found][cfg]

[cfg]: ./step4_cfg_main.png "CFGAccurate"