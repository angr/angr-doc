# Debug variable resolution

angr now support resolve source level variable (debug variable) in binary with debug information. This article will introduce you how to use it.

## Setting up

To use it you need binary that is compiled with debug information and load in angr with the option `load_debug_info`. After that you need to run `project.kb.dvars.load_from_dwarf()` to set up the feature and we're set.  

Overall it looks like this:
```python
>>> import angr
>>> project = angr.Project('your_binary_name', load_debug_info = True)
>>> project.kb.dvars.load_from_dwarf()
```

## Core feature

With things now set up you can view the value in the angr memory view of the debug variable within a state with: `state.dvars['variable_name'].mem` or the value that it point to if it is a pointer with: `state.dvars['pointer_name'].deref.mem`. Here are some example:

Given the source code:
```c
#include<stdio.h>

int main(void){
  int a = 10;
  int* b = &a;
  printf("%d\n", *b);
  {
    int a = 24;
    *b = *b + a;
    printf("%d\n", *b);
  }
  return 0;
}
```

```python
# Trying to resolve 'a' in state before execute line 6
>>> state.dvars['a'].mem
<int (32 bits) <BV32 0xa> at 0x7fffffffffeff48>
# Trying to dereference pointer b
>>> state.dvars['b'].deref.mem
<int (32 bits) <BV32 0xa> at 0x7fffffffffeff48>
# it works as expected when resolving the value of b gives the address of a
>>> state.dvars['b'].mem
<reg64_t <BV64 0x7fffffffffeff48> at 0x7fffffffffeff50>
```

Side-note:  
For string type you can use `.string` instead of `.mem` to resolve it.  
For struct type you can resolve its member by `.member("member_name")`.

# Variable visibility
If you have many variable with the same name but in different scope, calling `state.dvars['var_name']` would resolve the variable with the nearest scope.

Example:
```python
# Trying to resolve 'a' in state before execute line 10
>>> state.dvars['a'].mem
<int (32 bits) <BV32 0x18> at 0x7fffffffffeff4c>
```

Congratulation, you've now know how to resolve debug variable using angr, for more info check out the api-doc.
