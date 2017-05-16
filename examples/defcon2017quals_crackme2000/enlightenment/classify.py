import subprocess
from glob import glob
import re
from collections import defaultdict
import shutil
import os
import hashlib

files = glob('enlightenment_dist/*')
libraries = defaultdict(list)
ldds = {}

for f in files:
    try:
        ldd_out = subprocess.check_output(['ldd', f])
    except subprocess.CalledProcessError:
        continue
    libz = ""
    for line in ldd_out.splitlines():
        match = re.match(r'\t(.*) =>', line)
        if match:
            libz += match.group(1)
    k = hashlib.md5(libz).hexdigest()
    libraries[k].append(f)
    ldds[k] = ldd_out

print libraries.keys()
print ldds

# ['libchicken.so.7', 'libutil.so.1', 'libstdc++.so.6', 'librt.so.1', 'libgcc_s.so.1', 'libm.so.6', 'libpthread.so.0', 'libswiftCore.so', 'libdl.so.2', 'linux-vdso.so.1', 'libc.so.6', 'libswiftGlibc.so']
for k in libraries.keys():
    try:
        os.mkdir(k)
    except:
        pass
    for f in libraries[k]:
        try:
            shutil.move(f, k+'/')
        except:
            pass
