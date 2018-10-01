import sys
import subprocess

def test():
    print("Checking sokosolver_facuman.py solution...", file=sys.stderr)
    p = subprocess.Popen([ sys.executable, "sokosolver_facuman.py" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    out = p.stdout.read()
    assert b"[('x', (7, 22)), ('y', (18, 13)), ('z', (2, 5)), ('w', (4, 1))]" in out

    print("Checking sokosolver.py solution...", file=sys.stdout)
    p = subprocess.Popen([ sys.executable, "sokosolver.py" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    out = p.stdout.read()
    assert b"x:  0xf5b57de9c00229bd\ny:  0x24b17a4c0132a01\nz: 0x17c2b7a986200088\nw: 0x32b0dffbfc485d1e" in out

if __name__ == '__main__':
    test()
