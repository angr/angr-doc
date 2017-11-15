#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

FIND_ADDR = 0x0804848a
AVOID_ADDR = 0x0804847c

def main():
	proj = angr.Project('crackme0x03', load_options={"auto_load_libs": False})

	sm = proj.factory.simulation_manager()
	sm.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

	return sm.found[0].posix.dumps(0).lstrip('+0').rstrip('B')

def test():
	assert main() == '338724\00'

if __name__ == '__main__':
    print(repr(main()))

"""
[0x08048360]> pdf @ main
            ;-- main:
╒ (fcn) sym.main 128
│           ; var int local_4h @ ebp-0x4
│           ; var int local_8h @ ebp-0x8
│           ; var int local_ch @ ebp-0xc
│           ; var int arg_4h @ esp+0x4
│           ; UNKNOWN XREF from 0x08048378 (entry0)
│           ; DATA XREF from 0x08048377 (entry0)
│           0x08048498      55             push ebp
│           0x08048499      89e5           ebp = esp
│           0x0804849b      83ec18         esp -= 0x18
│           0x0804849e      83e4f0         esp &= 0xfffffff0
│           0x080484a1      b800000000     eax = 0
│           0x080484a6      83c00f         eax += 0xf
│           0x080484a9      83c00f         eax += 0xf
│           0x080484ac      c1e804         eax >>>= 4
│           0x080484af      c1e004         eax <<<= 4
│           0x080484b2      29c4           esp -= eax
│           0x080484b4      c70424108604.  dword [esp] = str.IOLI_Crackme_Level_0x03_n ; [0x8048610:4]=0x494c4f49 LEA str.IOLI_Crackme_Level_0x03_n ; "IOLI Crackme Level 0x03." @ 0x8048610
│           0x080484bb      e890feffff     sym.imp.printf ()
│           0x080484c0      c70424298604.  dword [esp] = str.Password: ; [0x8048629:4]=0x73736150 LEA str.Password: ; "Password: " @ 0x8048629
│           0x080484c7      e884feffff     sym.imp.printf ()
│           0x080484cc      8d45fc         eax = [ebp - local_4h]
│           0x080484cf      89442404       dword [esp + arg_4h] = eax
│           0x080484d3      c70424348604.  dword [esp] = 0x8048634     ; [0x8048634:4]=0x6425 ; "%d" @ 0x8048634
│           0x080484da      e851feffff     sym.imp.scanf ()
│           0x080484df      c745f85a0000.  dword [ebp - local_8h] = 0x5a
│           0x080484e6      c745f4ec0100.  dword [ebp - local_ch] = 0x1ec
│           0x080484ed      8b55f4         edx = dword [ebp - local_ch]
│           0x080484f0      8d45f8         eax = [ebp - local_8h]
│           0x080484f3      0110           dword [eax] += edx
│           0x080484f5      8b45f8         eax = dword [ebp - local_8h]
│           0x080484f8      0faf45f8       eax *= dword [ebp - local_8h]
│           0x080484fc      8945f4         dword [ebp - local_ch] = eax
│           0x080484ff      8b45f4         eax = dword [ebp - local_ch]
│           0x08048502      89442404       dword [esp + arg_4h] = eax
│           0x08048506      8b45fc         eax = dword [ebp - local_4h]
│           0x08048509      890424         dword [esp] = eax
│           0x0804850c      e85dffffff     sym.test ()
│           0x08048511      b800000000     eax = 0
│           0x08048516      c9
╘           0x08048517      c3
[0x08048460]> pdf @ sym.test
╒ (fcn) sym.test 42
│           ; arg int arg_8h @ ebp+0x8
│           ; arg int arg_ch @ ebp+0xc
│           ; CALL XREF from 0x0804850c (sym.main)
│           0x0804846e      55             push ebp
│           0x0804846f      89e5           ebp = esp
│           0x08048471      83ec08         esp -= 8
│           0x08048474      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│           0x08048477      3b450c         if (eax == dword [ebp + arg_ch] ; [0xc:4]=0
│       ┌─< 0x0804847a      740e           isZero 0x804848a)
│       │   0x0804847c      c70424ec8504.  dword [esp] = str.Lqydolg_Sdvvzrug_ ; [0x80485ec:4]=0x6479714c LEA str.Lqydolg_Sdvvzrug_ ; "Lqydolg#Sdvvzrug$" @ 0x80485ec
│       │   0x08048483      e88cffffff     sym.shift ()
│      ┌──< 0x08048488      eb0c           goto 0x8048496
│      │└─> 0x0804848a      c70424fe8504.  dword [esp] = str.Sdvvzrug_RN______ ; [0x80485fe:4]=0x76766453 LEA str.Sdvvzrug_RN______ ; "Sdvvzrug#RN$$$#=," @ 0x80485fe
│      │    0x08048491      e87effffff     sym.shift ()
│      │    ; JMP XREF from 0x08048488 (sym.test)
│      └──> 0x08048496      c9
╘           0x08048497      c3
"""
