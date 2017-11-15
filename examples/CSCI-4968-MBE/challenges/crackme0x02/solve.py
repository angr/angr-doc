#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

FIND_ADDR = 0x0804845f # Statement right after the OK printf.
AVOID_ADDR = 0x08048461 # dword [esp] = str.Invalid_Password__n ; [0x804857f:4]=0x61766e49 LEA str.Invalid_Password__n ; "Invalid Password!." @ 0x804857f

def main():
	proj = angr.Project('crackme0x02', load_options={"auto_load_libs": False})

	sm = proj.factory.simulation_manager()
	sm.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

	return sm.found[0].posix.dumps(0).lstrip('+0').rstrip('B')

def test():
	assert main() == '338724\00'

if __name__ == '__main__':
    print(repr(main()))

"""
 [0x08048330]> pdf @ main
            ;-- main:
╒ (fcn) sym.main 144
│           ; var int local_4h @ ebp-0x4
│           ; var int local_8h @ ebp-0x8
│           ; var int local_ch @ ebp-0xc
│           ; var int arg_4h @ esp+0x4
│           ; UNKNOWN XREF from 0x08048348 (entry0)
│           ; DATA XREF from 0x08048347 (entry0)
│           0x080483e4      55             push ebp
│           0x080483e5      89e5           ebp = esp
│           0x080483e7      83ec18         esp -= 0x18
│           0x080483ea      83e4f0         esp &= 0xfffffff0
│           0x080483ed      b800000000     eax = 0
│           0x080483f2      83c00f         eax += 0xf
│           0x080483f5      83c00f         eax += 0xf
│           0x080483f8      c1e804         eax >>>= 4
│           0x080483fb      c1e004         eax <<<= 4
│           0x080483fe      29c4           esp -= eax
│           0x08048400      c70424488504.  dword [esp] = str.IOLI_Crackme_Level_0x02_n ; [0x8048548:4]=0x494c4f49 LEA str.IOLI_Crackme_Level_0x02_n ; "IOLI Crackme Level 0x02." @ 0x8048548
│           0x08048407      e810ffffff     sym.imp.printf ()
│           0x0804840c      c70424618504.  dword [esp] = str.Password: ; [0x8048561:4]=0x73736150 LEA str.Password: ; "Password: " @ 0x8048561
│           0x08048413      e804ffffff     sym.imp.printf ()
│           0x08048418      8d45fc         eax = [ebp - local_4h]
│           0x0804841b      89442404       dword [esp + arg_4h] = eax
│           0x0804841f      c704246c8504.  dword [esp] = 0x804856c     ; [0x804856c:4]=0x50006425 ; "%d" @ 0x804856c
│           0x08048426      e8e1feffff     sym.imp.scanf ()
│           0x0804842b      c745f85a0000.  dword [ebp - local_8h] = 0x5a
│           0x08048432      c745f4ec0100.  dword [ebp - local_ch] = 0x1ec
│           0x08048439      8b55f4         edx = dword [ebp - local_ch]
│           0x0804843c      8d45f8         eax = [ebp - local_8h]
│           0x0804843f      0110           dword [eax] += edx
│           0x08048441      8b45f8         eax = dword [ebp - local_8h]
│           0x08048444      0faf45f8       eax *= dword [ebp - local_8h]
│           0x08048448      8945f4         dword [ebp - local_ch] = eax
│           0x0804844b      8b45fc         eax = dword [ebp - local_4h]
│           0x0804844e      3b45f4         if (eax == dword [ebp - local_ch]
│       ┌─< 0x08048451      750e           notZero 0x8048461)
│       │   0x08048453      c704246f8504.  dword [esp] = str.Password_OK_:__n ; [0x804856f:4]=0x73736150 LEA str.Password_OK_:__n ; "Password OK :)." @ 0x804856f
│       │   0x0804845a      e8bdfeffff     sym.imp.printf ()
│      ┌──< 0x0804845f      eb0c           goto 0x804846d
│      │└─> 0x08048461      c704247f8504.  dword [esp] = str.Invalid_Password__n ; [0x804857f:4]=0x61766e49 LEA str.Invalid_Password__n ; "Invalid Password!." @ 0x804857f
│      │    0x08048468      e8affeffff     sym.imp.printf ()
│      │    ; JMP XREF from 0x0804845f (sym.main)
│      └──> 0x0804846d      b800000000     eax = 0
│           0x08048472      c9
╘           0x08048473      c3
"""
