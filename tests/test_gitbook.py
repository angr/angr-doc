# pylint: disable=exec-used
import os
import sys
import traceback
import itertools
import claripy

def _path(d):
    return os.path.join(os.path.dirname(__file__), '..', d)

md_files = filter(lambda s: s.endswith('.md'), [
    os.path.join(_path('docs'), t) for t in os.listdir(_path('docs'))
])
md_files += filter(lambda s: s.endswith('.md'), [
    os.path.join(_path('docs/analyses'), t) for t in os.listdir(_path('docs/analyses'))
])
md_files += filter(lambda s: s.endswith('.md'), [
    os.path.join(_path('docs/courses'), t) for t in os.listdir(_path('docs/courses'))
])
example_dirs = filter(lambda s: '.' not in s, os.listdir(_path('examples')))

sys.path.append('.')

def doctest_single(md_file):
    orig_path = os.getcwd()
    os.chdir(_path('.'))
    try:
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
                print 'Error on line %d of %s: %s' % (i+1, md_file, e)
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
