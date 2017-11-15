#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

FIND_ADDR = 0x0804844e # This is right after the printf for the OK password.
AVOID_ADDR = 0x08048434 # mov dword [esp], str.Invalid_Password__n ; [0x804854f:4]=0x61766e49 LEA str.Invalid_Password__n ; "Invalid Password!." @ 0x804854f

def main():
	proj = angr.Project('crackme0x01', load_options={"auto_load_libs": False})

	sm = proj.factory.simulation_manager()
	sm.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

	return sm.found[0].posix.dumps(0).lstrip('+0').rstrip('B')

def test():
	assert main() == '5274\n'

if __name__ == '__main__':
	print(repr(main()))

"""
[0x08048530]> pdf @ main
            ;-- main:
╒ (fcn) sym.main 113
│           ; arg int arg_149ah @ ebp+0x149a
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
│           0x08048400      c70424288504.  dword [esp] = str.IOLI_Crackme_Level_0x01_n ; [0x8048528:4]=0x494c4f49 LEA str.IOLI_Crackme_Level_0x01_n ; "IOLI Crackme Level 0x01." @ 0x8048528
│           0x08048407      e810ffffff     sym.imp.printf ()
│           0x0804840c      c70424418504.  dword [esp] = str.Password: ; [0x8048541:4]=0x73736150 LEA str.Password: ; "Password: " @ 0x8048541
│           0x08048413      e804ffffff     sym.imp.printf ()
│           0x08048418      8d45fc         eax = [ebp - local_4h]
│           0x0804841b      89442404       dword [esp + arg_4h] = eax
│           0x0804841f      c704244c8504.  dword [esp] = 0x804854c     ; [0x804854c:4]=0x49006425 ; "%d" @ 0x804854c
│           0x08048426      e8e1feffff     sym.imp.scanf ()
│           0x0804842b      817dfc9a1400.  if (dword [ebp - local_4h] == 0x149a ; [0x149a:4]=0x2ec0804
│       ┌─< 0x08048432      740e           isZero 0x8048442)
│       │   0x08048434      c704244f8504.  dword [esp] = str.Invalid_Password__n ; [0x804854f:4]=0x61766e49 LEA str.Invalid_Password__n ; "Invalid Password!." @ 0x804854f
│       │   0x0804843b      e8dcfeffff     sym.imp.printf ()
│      ┌──< 0x08048440      eb0c           goto 0x804844e
│      │└─> 0x08048442      c70424628504.  dword [esp] = str.Password_OK_:__n ; [0x8048562:4]=0x73736150 LEA str.Password_OK_:__n ; "Password OK :)." @ 0x8048562
│      │    0x08048449      e8cefeffff     sym.imp.printf ()
│      │    ; JMP XREF from 0x08048440 (sym.main)
│      └──> 0x0804844e      b800000000     eax = 0
│           0x08048453      c9
╘           0x08048454      c3
"""
