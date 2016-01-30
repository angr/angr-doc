# pylint: disable=exec-used
import os
import sys
import claripy
import itertools

md_files = filter(lambda s: s.endswith('.md'), os.listdir('.'))
example_dirs = filter(lambda s: '.' not in s, os.listdir('examples'))

sys.path.append('.')
def exampletest_single(example_dir):
    os.chdir('examples/' + example_dir)
    print os.getcwd()
    try:
        s = __import__('solve')
        s = reload(s)
        s.test()
    finally:
        os.chdir('../..')

def doctest_single(md_file):
    claripy.ast.base.var_counter = itertools.count()
    lines = open(md_file).read().split('\n')
    test_enabled = False
    multiline_enabled = False
    multiline_stuff = ''
    env = {}

    def try_running(line, i):
        try:
            exec line in env
        except Exception as e:
            raise Exception('Error on line %d of %s: %s' % (i+1, md_file, e))

    for i, line in enumerate(lines):
        if test_enabled:
            if line == '```':
                test_enabled = False
            else:
                if not multiline_enabled:
                    if line.startswith('>>> '):
                        line = line[4:]
                        if lines[i+1].startswith('... '):
                            multiline_enabled = True
                            multiline_stuff = line + '\n'
                        else:
                            try_running(line, i)
                else:
                    assert line.startswith('... ')
                    line = line[4:]
                    multiline_stuff += line + '\n'
                    if not lines[i+1].startswith('... '):
                        multiline_enabled = False
                        try_running(multiline_stuff, i)
        else:
            if line == '```python':
                test_enabled = True

def test_docs():
    for md_file in md_files:
        yield doctest_single, md_file

#def test_9447_nobranch(): exampletest_single('9447_nobranch')
def test_ais3_crackme(): exampletest_single('ais3_crackme')
def test_asisctffinals2015_fake(): exampletest_single('asisctffinals2015_fake')
def test_asisctffinals2015_license(): exampletest_single('asisctffinals2015_license')
def test_CADET_00001(): exampletest_single('CADET_00001')
def test_cmu_binary_bomb(): exampletest_single('cmu_binary_bomb')
#def test_csaw_wyvern(): exampletest_single('csaw_wyvern')
def test_defcamp_r100(): exampletest_single('defcamp_r100')
def test_defcamp_r200(): exampletest_single('defcamp_r200')
def test_ekopartyctf2015_rev100(): exampletest_single('ekopartyctf2015_rev100')
def test_fauxware(): exampletest_single('fauxware')
def test_flareon2015_10(): exampletest_single('flareon2015_10')
def test_flareon2015_2(): exampletest_single('flareon2015_2')
#def test_flareon2015_5(): exampletest_single('flareon2015_5')
def test_grub(): exampletest_single('grub')
#def test_layer7_onlyone(): exampletest_single('layer7_onlyone')
def test_mma_howtouse(): exampletest_single('mma_howtouse')
#def test_mma_simplehash(): exampletest_single('mma_simplehash')
def test_strcpy_find(): exampletest_single('strcpy_find')
def test_whitehat_crypto400(): exampletest_single('whitehat_crypto400')
def test_whitehatvn2015_re400(): exampletest_single('whitehatvn2015_re400')

if __name__ == '__main__':
    for tester, arg in test_docs():
        tester(arg)
