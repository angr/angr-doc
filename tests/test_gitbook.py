# pylint: disable=exec-used
import os
import unittest
import sys
import traceback
import itertools
import claripy

# pylint: disable=missing-class-docstring, no-self-use
class TestGitbook(unittest.TestCase):

    def setUp(self):
        self.filepath = __file__

        self.md_files = []
        for _p in ('docs', 'docs/analyses', 'docs/courses'):
            self.md_files += [os.path.join(_p, t) for t in os.listdir(self._path(_p)) if t.endswith('.md')]

    def _path(self, d):
        return os.path.join(os.path.dirname(self.filepath), '..', d)

    def doctest_single(self, md_file):
        orig_path = os.getcwd()
        os.chdir(self._path('.'))
        try:
            claripy.ast.base.var_counter = itertools.count()
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
                    raise Exception('Error on line %d of %s: %s' % (i+1, md_file, e)) from e

            with open(md_file,"r", encoding='utf-8') as file:
                lines = [line.rstrip('\n') for line in file]
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

    def test_docs(self):
        sys.path.append('.')
        for md_file in self.md_files:
            self.doctest_single(md_file)
        sys.path.pop()

if __name__ == '__main__':
    unittest.main()
