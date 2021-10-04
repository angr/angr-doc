#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr
import subprocess

def main():
    proj = angr.Project('crackme0x05', load_options={"auto_load_libs": False})

    def correct(state):
        try:
            return b'Password OK' in state.posix.dumps(1)
        except:
            return False

    def wrong(state):
        try:
            return b'Password Incorrect' in state.posix.dumps(1)
        except:
            return False

    sm = proj.factory.simulation_manager()
    sm.explore(find=correct, avoid=wrong)

    #print(sm.found[0].posix.dumps(1))
    return sm.found[0].posix.dumps(0) # .lstrip('+0').rstrip('B')

def test():
	# it SHOULD just be two numbers but the way angr models scanf means that it could technically be any number of formats
	# so we gotta check against ground truth
	with open('input', 'wb') as fp:
		fp.write(main())

	assert subprocess.check_output('./crackme0x05 < input', shell=True) == b'IOLI Crackme Level 0x05\nPassword: Password OK!\n'

if __name__ == '__main__':
	print(repr(main()))

"""
[0x080483d0]> pdf @ main
            ;-- main:
╒ (fcn) sym.main 92
│           ; var int local_78h @ ebp-0x78
│           ; var int arg_4h @ esp+0x4
│           ; UNKNOWN XREF from 0x080483e8 (entry0)
│           ; DATA XREF from 0x080483e7 (entry0)
│           0x08048540      55             push ebp
│           0x08048541      89e5           ebp = esp
│           0x08048543      81ec88000000   esp -= 0x88
│           0x08048549      83e4f0         esp &= 0xfffffff0
│           0x0804854c      b800000000     eax = 0
│           0x08048551      83c00f         eax += 0xf
│           0x08048554      83c00f         eax += 0xf
│           0x08048557      c1e804         eax >>>= 4
│           0x0804855a      c1e004         eax <<<= 4
│           0x0804855d      29c4           esp -= eax
│           0x0804855f      c704248e8604.  dword [esp] = str.IOLI_Crackme_Level_0x05_n ; [0x804868e:4]=0x494c4f49 LEA str.IOLI_Crackme_Level_0x05_n ; "IOLI Crackme Level 0x05." @ 0x804868e
│           0x08048566      e829feffff     sym.imp.printf ()
│           0x0804856b      c70424a78604.  dword [esp] = str.Password: ; [0x80486a7:4]=0x73736150 LEA str.Password: ; "Password: " @ 0x80486a7
│           0x08048572      e81dfeffff     sym.imp.printf ()
│           0x08048577      8d4588         eax = [ebp - local_78h]
│           0x0804857a      89442404       dword [esp + arg_4h] = eax
│           0x0804857e      c70424b28604.  dword [esp] = 0x80486b2     ; [0x80486b2:4]=0x7325 ; "%s" @ 0x80486b2
│           0x08048585      e8eafdffff     sym.imp.scanf ()
│           0x0804858a      8d4588         eax = [ebp - local_78h]
│           0x0804858d      890424         dword [esp] = eax
│           0x08048590      e833ffffff     sym.check ()
│           0x08048595      b800000000     eax = 0
│           0x0804859a      c9
╘           0x0804859b      c3
[0x080483d0]> pdf @ sym.check
╒ (fcn) sym.check 120
│           ; arg int arg_8h @ ebp+0x8
│           ; arg int arg_10h @ ebp+0x10
│           ; arg int arg_13h @ ebp+0x13
│           ; var int arg_4h @ esp+0x4
│           ; var int arg_8h @ esp+0x8
│           ; CALL XREF from 0x08048590 (sym.main)
│           0x080484c8      55             push ebp
│           0x080484c9      89e5           ebp = esp
│           0x080484cb      83ec28         esp -= 0x28
│           0x080484ce      c745f8000000.  dword [ebp - local_8h] = 0
│           0x080484d5      c745f4000000.  dword [ebp - local_ch] = 0
│           ; JMP XREF from 0x08048530 (sym.check)
│       ┌─> 0x080484dc      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│       │   0x080484df      890424         dword [esp] = eax
│       │   0x080484e2      e89dfeffff     sym.imp.strlen ()
│       │   0x080484e7      3945f4         if (dword [ebp - local_ch] == eax ; [0x13:4]=256
│      ┌──< 0x080484ea      7346           jae 0x8048532
│      ││   0x080484ec      8b45f4         eax = dword [ebp - local_ch]
│      ││   0x080484ef      034508         eax += dword [ebp + arg_8h]
│      ││   0x080484f2      0fb600         eax = byte [eax]
│      ││   0x080484f5      8845f3         byte [ebp - local_dh] = al
│      ││   0x080484f8      8d45fc         eax = [ebp - local_4h]
│      ││   0x080484fb      89442408       dword [esp + arg_8h] = eax
│      ││   0x080484ff      c74424046886.  dword [esp + arg_4h] = 0x8048668 ; [0x8048668:4]=0x50006425 ; "%d" @ 0x8048668
│      ││   0x08048507      8d45f3         eax = [ebp - local_dh]
│      ││   0x0804850a      890424         dword [esp] = eax
│      ││   0x0804850d      e892feffff     sym.imp.sscanf ()
│      ││   0x08048512      8b55fc         edx = dword [ebp - local_4h]
│      ││   0x08048515      8d45f8         eax = [ebp - local_8h]
│      ││   0x08048518      0110           dword [eax] += edx
│      ││   0x0804851a      837df810       if (dword [ebp - local_8h] == 0x10 ; [0x10:4]=0x30002
│     ┌───< 0x0804851e      750b           notZero 0x804852b)
│     │││   0x08048520      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│     │││   0x08048523      890424         dword [esp] = eax
│     │││   0x08048526      e859ffffff     sym.parell ()
│     └───> 0x0804852b      8d45f4         eax = [ebp - local_ch]
│      ││   0x0804852e      ff00           dword [eax]++
│      │└─< 0x08048530      ebaa           goto 0x80484dc
│      └──> 0x08048532      c70424798604.  dword [esp] = str.Password_Incorrect__n ; [0x8048679:4]=0x73736150 LEA str.Password_Incorrect__n ; "Password Incorrect!." @ 0x8048679
│           0x08048539      e856feffff     sym.imp.printf ()
│           0x0804853e      c9
╘           0x0804853f      c3
"""
