### Project

- This is to demonstrate how to work with `angr` on a static/stripped binary

### Source

- Source `angrtest.c`
```c
#include <stdio.h>

void success() {
    printf("Success!\n");
}


void main(){
    int buffer[100];
    printf("Input password: ");
    scanf("%99s", buffer);
    if (strcmp(buffer,"12345")==0)
        success();
    else
        printf("fail\n");
}
```
- Compile using: `gcc -s --static -o angrtest-stripped angrtest.c`
- Compilation was done on `Ubuntu 16.04.03 LTS`

### Symbols

- The binary is stripped, so we need to 'manually' identitify `main` and the library functions
- I've currently solved this by using IDA Pro FLiRT signatures
    + Get `libc.a` from `libc6-dev`
    + Get `IDA\ Pro\ 7.0/idasdk70b6/flair70/bin/`
    + Use `pelf libc.a x86_64-linux-gnu-libc.a.pat`
    + Use `sigmake -n'x86_64-linux-gnu-libc.a' x86_64-linux-gnu-libc.a.pat x86_64-linux-gnu-libc.a.sig`
    + 'Resolve' issues by removing the first 4 lines of `x86_64-linux-gnu-libc.a.exc`
    + Use `sigmake -n'x86_64-linux-gnu-libc.a' x86_64-linux-gnu-libc.a.pat x86_64-linux-gnu-libc.a.sig` again.
    + Copy `x86_64-linux-gnu-libc.a.sig` to `/Applications/IDA\ Pro\ 7.0/ida64.app/Contents/MacOS/sig/pc/`
    + In IDA apply the signature: `File -> Load file -> FLiRT signature file`
    + Signatures should now (partially) resolve some important functions
- After the symbols have resolved, we can now identify the addresses of `printf` `scanf` and `strcmp`, inside function `main`.
- To identify `main`, checkout `start`
```ida
.text:0000000000400890                 public start
.text:0000000000400890 start           proc near               ; DATA XREF: LOAD:0000000000400018↑o
.text:0000000000400890 ; __unwind {
.text:0000000000400890                 xor     ebp, ebp
.text:0000000000400892                 mov     r9, rdx
.text:0000000000400895                 pop     rsi
.text:0000000000400896                 mov     rdx, rsp
.text:0000000000400899                 and     rsp, 0FFFFFFFFFFFFFFF0h
.text:000000000040089D                 push    rax
.text:000000000040089E                 push    rsp
.text:000000000040089F                 mov     r8, offset __libc_csu_fini
.text:00000000004008A6                 mov     rcx, offset __libc_csu_init
.text:00000000004008AD                 mov     rdi, offset sub_4009BF
.text:00000000004008B4                 call    __libc_start_main
.text:00000000004008B4 start           endp
```
- Rename `sub_4009BF` to `main` in IDA
- Checkout the mentioned library functions in `main`, they should have resolved.

### angr

- We want to start solving from the `main` function. We therefore specify that address as our start state. Eg: 
```python
ADDR_main = 0x00000000004009BF
start_state = proj.factory.blank_state(addr=ADDR_main)
```
- Since the binary has no symbols, we should tell `Angr` about the library functions being called. Eg: 
```python
ADDR_printf = 0x000000000040F380
proj.hook(ADDR_printf, angr.procedures.libc.printf.printf)
```
- Identify the address of the `success` function manually. This should be the the place to search for. Eg: 
```python
ADDR_success = 0x00000000004009AE
simgr.explore(find=ADDR_success)
```

- The full script:

```python
import angr

binary = 'angrtest-stripped'

ADDR_main = 0x00000000004009BF
ADDR_success = 0x00000000004009AE
ADDR_printf = 0x000000000040F380
ADDR_scanf = 0x00000000040F4B0
ADDR_strcmp = 0x0000000000400360

proj = angr.Project(binary)
start_state = proj.factory.blank_state(addr=ADDR_main)
simgr = proj.factory.simulation_manager(start_state)

proj.hook(ADDR_printf, angr.procedures.libc.printf.printf())
proj.hook(ADDR_scanf, angr.procedures.libc.scanf.scanf())
proj.hook(ADDR_strcmp, angr.procedures.libc.strcmp.strcmp())
simgr.explore(find=ADDR_success)

print('Input: \n{}'.format(simgr.found[0].posix.dumps(0)))
print('Std output: \n{}'.format(simgr.found[0].posix.dumps(1)))
```

- Output:
```
WARNING | 2018-01-05 14:08:56,278 | angr.analyses.disassembly_utils | Your verison of capstone does not support MIPS instruction groups.
CRITICAL | 2018-01-05 14:08:56,562 | angr.project | Hooking with a SimProcedure class is deprecated! Please hook with an instance.
Input:
12345
Std output:
Input password:
```
