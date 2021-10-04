#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr
import subprocess

# from IPython import embed # pop iPython at the end

def main():
	proj = angr.Project('crackme0x04', load_options={"auto_load_libs": False})

	cfg = proj.analyses.CFG()
	FIND_ADDR = cfg.kb.functions.function(name="exit").addr
	AVOID_ADDR = 0x080484fb # dword [esp] = str.Password_Incorrect__n ; [0x8048649:4]=0x73736150 LEA str.Password_Incorrect__n ; "Password Incorrect!." @ 0x8048649

	sm = proj.factory.simulation_manager()
	sm.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

	# embed()
	#print(sm.found[0].posix.dumps(1))
	return sm.found[0].posix.dumps(0) # .lstrip('+0').rstrip('B')

def test():
	# it SHOULD just be 96 but the way angr models scanf means that it could technically be any number of formats
	# so we gotta check against ground truth
	with open('input', 'wb') as fp:
		fp.write(main())

	assert subprocess.check_output('./crackme0x04 < input', shell=True) == b'IOLI Crackme Level 0x04\nPassword: Password OK!\n'

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
│           0x08048509      55             push ebp
│           0x0804850a      89e5           ebp = esp
│           0x0804850c      81ec88000000   esp -= 0x88
│           0x08048512      83e4f0         esp &= 0xfffffff0
│           0x08048515      b800000000     eax = 0
│           0x0804851a      83c00f         eax += 0xf
│           0x0804851d      83c00f         eax += 0xf
│           0x08048520      c1e804         eax >>>= 4
│           0x08048523      c1e004         eax <<<= 4
│           0x08048526      29c4           esp -= eax
│           0x08048528      c704245e8604.  dword [esp] = str.IOLI_Crackme_Level_0x04_n ; [0x804865e:4]=0x494c4f49 LEA str.IOLI_Crackme_Level_0x04_n ; "IOLI Crackme Level 0x04." @ 0x804865e
│           0x0804852f      e860feffff     sym.imp.printf ()
│           0x08048534      c70424778604.  dword [esp] = str.Password: ; [0x8048677:4]=0x73736150 LEA str.Password: ; "Password: " @ 0x8048677
│           0x0804853b      e854feffff     sym.imp.printf ()
│           0x08048540      8d4588         eax = [ebp - local_78h]
│           0x08048543      89442404       dword [esp + arg_4h] = eax
│           0x08048547      c70424828604.  dword [esp] = 0x8048682     ; [0x8048682:4]=0x7325 ; "%s" @ 0x8048682
│           0x0804854e      e821feffff     sym.imp.scanf ()
│           0x08048553      8d4588         eax = [ebp - local_78h]
│           0x08048556      890424         dword [esp] = eax
│           0x08048559      e826ffffff     sym.check ()
│           0x0804855e      b800000000     eax = 0
│           0x08048563      c9
╘           0x08048564      c3
[0x080483d0]> pdf @ sym.check
╒ (fcn) sym.check 133
│           ; arg int arg_8h @ ebp+0x8
│           ; arg int arg_fh @ ebp+0xf
│           ; arg int arg_13h @ ebp+0x13
│           ; var int arg_4h @ esp+0x4
│           ; var int arg_8h @ esp+0x8
│           ; CALL XREF from 0x08048559 (sym.main)
│           0x08048484      55             push ebp
│           0x08048485      89e5           ebp = esp
│           0x08048487      83ec28         esp -= 0x28
│           0x0804848a      c745f8000000.  dword [ebp - local_8h] = 0
│           0x08048491      c745f4000000.  dword [ebp - local_ch] = 0
│           ; JMP XREF from 0x080484f9 (sym.check)
│       ┌─> 0x08048498      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│       │   0x0804849b      890424         dword [esp] = eax
│       │   0x0804849e      e8e1feffff     sym.imp.strlen ()
│       │   0x080484a3      3945f4         if (dword [ebp - local_ch] == eax ; [0x13:4]=256
│      ┌──< 0x080484a6      7353           jae 0x80484fb
│      ││   0x080484a8      8b45f4         eax = dword [ebp - local_ch]
│      ││   0x080484ab      034508         eax += dword [ebp + arg_8h]
│      ││   0x080484ae      0fb600         eax = byte [eax]
│      ││   0x080484b1      8845f3         byte [ebp - local_dh] = al
│      ││   0x080484b4      8d45fc         eax = [ebp - local_4h]
│      ││   0x080484b7      89442408       dword [esp + arg_8h] = eax
│      ││   0x080484bb      c74424043886.  dword [esp + arg_4h] = 0x8048638 ; [0x8048638:4]=0x50006425 ; "%d" @ 0x8048638
│      ││   0x080484c3      8d45f3         eax = [ebp - local_dh]
│      ││   0x080484c6      890424         dword [esp] = eax
│      ││   0x080484c9      e8d6feffff     sym.imp.sscanf ()
│      ││   0x080484ce      8b55fc         edx = dword [ebp - local_4h]
│      ││   0x080484d1      8d45f8         eax = [ebp - local_8h]
│      ││   0x080484d4      0110           dword [eax] += edx
│      ││   0x080484d6      837df80f       if (dword [ebp - local_8h] == 0xf ; [0xf:4]=0x3000200
│     ┌───< 0x080484da      7518           notZero 0x80484f4)
│     │││   0x080484dc      c704243b8604.  dword [esp] = str.Password_OK__n ; [0x804863b:4]=0x73736150 LEA str.Password_OK__n ; "Password OK!." @ 0x804863b
│     │││   0x080484e3      e8acfeffff     sym.imp.printf ()
│     │││   0x080484e8      c70424000000.  dword [esp] = 0
│     │││   0x080484ef      e8c0feffff     sym.imp.exit ()
│     └───> 0x080484f4      8d45f4         eax = [ebp - local_ch]
│      ││   0x080484f7      ff00           dword [eax]++
│      │└─< 0x080484f9      eb9d           goto 0x8048498
│      └──> 0x080484fb      c70424498604.  dword [esp] = str.Password_Incorrect__n ; [0x8048649:4]=0x73736150 LEA str.Password_Incorrect__n ; "Password Incorrect!." @ 0x8048649
│           0x08048502      e88dfeffff     sym.imp.printf ()
│           0x08048507      c9
╘           0x08048508      c3
"""
