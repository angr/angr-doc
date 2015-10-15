# pylint: disable=exec-used
import os
import claripy
import itertools

md_files = filter(lambda s: s.endswith('.md'), os.listdir('.'))

def test_docs():
    for md_file in md_files:
        yield doctest_single, md_file

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
