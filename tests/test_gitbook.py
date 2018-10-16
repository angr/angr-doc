# pylint: disable=exec-used
import os
import sys
import traceback
import itertools
import claripy

filepath = __file__

def _path(d):
    return os.path.join(os.path.dirname(filepath), '..', d)

md_files = []
for _p in ('docs', 'docs/analyses', 'docs/courses'):
    md_files += [os.path.join(_p, t) for t in os.listdir(_path(_p)) if t.endswith('.md')]
example_dirs = [s for s in os.listdir(_path('examples')) if '.' not in s]

sys.path.append('.')

def doctest_single(md_file):
    orig_path = os.getcwd()
    os.chdir(_path('.'))
    try:
        claripy.ast.base.var_counter = itertools.count()
        lines = open(md_file, encoding='utf-8').read().split('\n')
        test_enabled = False
        multiline_enabled = False
        multiline_stuff = ''
        env = {}

        def try_running(line, i):
            try:
                exec(line, env)
            except Exception as e:
                print('Error on line %d of %s: %s' % (i+1, md_file, e))
                traceback.print_exc()
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
    finally:
        os.chdir(orig_path)

def test_docs():
    for md_file in md_files:
        yield doctest_single, md_file

if __name__ == '__main__':
    for tester, arg in test_docs():
        tester(arg)
