import sys
import subprocess

def test():
    print >>sys.stderr, "Checking sokosolver_facuman.py solution..."
    p = subprocess.Popen([ sys.executable, "sokosolver_facuman.py" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    out = p.stdout.read()
    assert "[('x', (7, 22)), ('y', (18, 13)), ('z', (2, 5)), ('w', (4, 1))]" in out

    print >>sys.stderr, "Checking sokosolver.py solution..."
    p = subprocess.Popen([ sys.executable, "sokosolver.py" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    out = p.stdout.read()
    assert "x:  0xf5b57de9c00229bdL\ny:  0x24b17a4c0132a01L\nz: 0x17c2b7a986200088L\nw: 0x32b0dffbfc485d1eL" in out

if __name__ == '__main__':
    test()
