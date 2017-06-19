# Identifier


The identifier uses test cases to identify common library functions in CGC binaries.
It prefilters by finding some basic information about stack variables/arguments.
The information of about stack variables can be generally useful in other projects.

```python
>>> import angr

# get all the matches
>>> p = angr.Project("../binaries/tests/i386/identifiable")
>>> idfer = p.analyses.Identifier()
# note that .run() yields results so make sure to iterate through them or call list() etc
>>> for addr, symbol in idfer.run():
... 	print hex(addr), symbol

0x8048e60 memcmp
0x8048ef0 memcpy
0x8048f60 memmove
0x8049030 memset
0x8049320 fdprintf
0x8049a70 sprintf
0x8049f40 strcasecmp
0x804a0f0 strcmp
0x804a190 strcpy
0x804a260 strlen
0x804a3d0 strncmp
0x804a620 strtol
0x804aa00 strtol
0x80485b0 free
0x804aab0 free
0x804aad0 free
0x8048660 malloc
0x80485b0 free
```