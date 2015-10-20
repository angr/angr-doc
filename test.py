# pylint: disable=exec-used
import os
import sys
import claripy
import itertools

md_files = filter(lambda s: s.endswith('.md'), os.listdir('.'))
example_dirs = filter(lambda s: '.' not in s, os.listdir('examples'))

def test_docs():
    for md_file in md_files:
        yield doctest_single, md_file

def test_examples():
    sys.path.append('.')
    for example_dir in example_dirs:
        if example_dir in ('mma_simplehash', 
                           'csaw_wyvern', 
                           'layer7_onlyone', # Runs out of memory on the test machine
                           'whitehat_crypto400', # The binary must be ran in a privileged docker container
                           ):
            continue
        yield exampletest_single, example_dir

def exampletest_single(example_dir):
    os.chdir('examples/' + example_dir)
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
            exec(line, env)
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

if __name__ == '__main__':
    for tester, arg in test_docs():
        tester(arg)
