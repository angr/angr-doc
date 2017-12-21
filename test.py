# pylint: disable=exec-used
import os
import sys
import itertools
import traceback
import subprocess

from nose.plugins.attrib import attr

import claripy

def _path(d):
    return os.path.join(os.path.dirname(__file__), d)

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
def exampletest_single(example_dir):
    init_pwd = os.getcwd()
    os.chdir(_path('examples/') + example_dir)
    print os.getcwd()
    try:
        s = __import__('solve')
        s = reload(s)
        s.test()
    finally:
        os.chdir(init_pwd)

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

def test_docs():
    os.chdir(_path('.'))
    for md_file in md_files:
        yield doctest_single, md_file

## BEGIN EXAMPLE TESTS
#@attr(speed='slow')
#def test_9447_nobranch(): exampletest_single('9447_nobranch')
def test_0ctf_trace():  exampletest_single('0ctf_trace')
def test_ais3_crackme(): exampletest_single('ais3_crackme')
#@attr(speed='slow')
#def test_asisctffinals2015_fake(): exampletest_single('asisctffinals2015_fake')
def test_asisctffinals2015_license(): exampletest_single('asisctffinals2015_license')
def test_CADET_00001(): exampletest_single('CADET_00001')
@attr(speed='slow')
def test_cmu_binary_bomb(): exampletest_single('cmu_binary_bomb')
@attr(speed='slow')
def test_csaw_wyvern(): exampletest_single('csaw_wyvern')
def test_defcamp_r100(): exampletest_single('defcamp_r100')
def test_defcamp_r200(): exampletest_single('defcamp_r200')
def test_ekopartyctf2015_rev100(): exampletest_single('ekopartyctf2015_rev100')
def test_ekopartyctf2016_rev250(): exampletest_single('ekopartyctf2016_rev250')
def test_ekopartyctf2016_sokohashv2(): exampletest_single('ekopartyctf2016_sokohashv2')
def test_fauxware(): exampletest_single('fauxware')
def test_flareon2015_10(): exampletest_single('flareon2015_10')
def test_flareon2015_2(): exampletest_single('flareon2015_2')
@attr(speed='slow')
def test_flareon2015_5(): exampletest_single('flareon2015_5')
def test_google2016_unbreakable_0(): exampletest_single('google2016_unbreakable_0')
def test_google2016_unbreakable_1(): exampletest_single('google2016_unbreakable_1')
def test_grub(): exampletest_single('grub')
@attr(speed='slow')
def test_layer7_onlyone(): exampletest_single('layer7_onlyone')
def test_mma_howtouse(): exampletest_single('mma_howtouse')
@attr(speed='slow')
def test_mma_simplehash(): exampletest_single('mma_simplehash')
def test_securityfest_fairlight(): exampletest_single('securityfest_fairlight')
def test_strcpy_find(): exampletest_single('strcpy_find')
def test_whitehat_crypto400(): exampletest_single('whitehat_crypto400')
def test_whitehatvn2015_re400(): exampletest_single('whitehatvn2015_re400')
def test_secconquals2016_ropsynth(): exampletest_single('secconquals2016_ropsynth')
@attr(speed='slow')
def test_0ctf_momo_3(): exampletest_single('0ctf_momo_3')
def test_defcon2016quals_baby_re_0(): exampletest_single('defcon2016quals_baby-re_0')
def test_defcon2016quals_baby_re_1(): exampletest_single('defcon2016quals_baby-re_1')
def test_sharif7_rev50(): exampletest_single(os.path.join('sharif7', 'rev50'))
def test_simple_heap_overflow(): exampletest_single('simple_heap_overflow')
def test_csci_0a(): exampletest_single('CSCI-4968-MBE/challenges/crackme0x00a')
def test_csci_1(): exampletest_single('CSCI-4968-MBE/challenges/crackme0x01')
def test_csci_2(): exampletest_single('CSCI-4968-MBE/challenges/crackme0x02')
def test_csci_3(): exampletest_single('CSCI-4968-MBE/challenges/crackme0x03')
def test_csci_4(): exampletest_single('CSCI-4968-MBE/challenges/crackme0x04')
def test_csci_5(): exampletest_single('CSCI-4968-MBE/challenges/crackme0x05')
def test_insomnihack_aeg(): exampletest_single('insomnihack_aeg')
def test_android_license(): exampletest_single('android_arm_license_validation')
def test_sym_write(): exampletest_single('sym-write')
@attr(speed='slow')
def test_angry_reverser(): exampletest_single('hackcon2016_angry-reverser')
def test_sharif7(): exampletest_single('sharif7_rev50')
def test_angrybird(): exampletest_single('codegate_2017-angrybird')
@attr(speed='slow')
def test_mbrainfuzz(): exampletest_single('secuinside2016mbrainfuzz')
def test_unmapped_analysis(): exampletest_single('unmapped_analysis')
@attr(speed='slow')
def test_zwiebel(): exampletest_single('tumctf2016_zwiebel')
## END EXAMPLE TESTS

def test_example_inclusion():
    to_test = subprocess.check_output(['/bin/bash', '-c', 'for c in $(find -name solve.py | cut -c 3-); do echo ${c%/solve.py}; done'], cwd=os.path.join(os.path.dirname(__file__), 'examples'))
    with open(__file__) as fp:
        test_source = fp.read()
    example_tests = test_source[test_source.find('## BEGIN EXAMPLE TESTS'):test_source.find('## END EXAMPLE TESTS')]

    missing = []
    for line in to_test.strip().split('\n'):
        if ("exampletest_single('%s')" % line) not in example_tests:
            missing.append(line)
    if missing:
        raise Exception("The following examples are not represented in the test corpus:\n" + '\n'.join(missing))

def test_api_coverage():
    missing = []
    exclude = ['angr.tablespecs', 'angr.service', 'pyvex.vex_ffi']
    exclude_prefix = ['angr.procedures', 'angr.analyses.identifier', 'angr.misc', 'angr.surveyors', 'angr.engines.vex', 'claripy.utils']
    for module in ['angr', 'claripy', 'cle', 'pyvex', 'archinfo']:
        docs_file = 'api-doc/source/%s.rst' % module
        module_dir = '../%s/%s' % (module, module)
        module_list = subprocess.check_output('find -name \'*.py\'', cwd=module_dir, shell=True).split()
        api_list = [x.split()[-1] for x in open(docs_file).readlines() if 'automodule' in x]
        for partial in module_list:
            full = module + '.' + partial[2:-3].replace('/', '.')
            if full.endswith('.__init__'):
                full = full[:-9]

            if full not in api_list and full not in exclude:
                for ep in exclude_prefix:
                    if full.startswith(ep):
                        break
                else:
                    missing.append(full)

    if missing:
        raise Exception("The following modules are not represnted in the api docs:\n" + '\n'.join(missing))

if __name__ == '__main__':
    test_example_inclusion()
    test_api_coverage()

    for tester, arg in test_docs():
        tester(arg)

    for fname, func in globals().items():
        if callable(func) and fname.startswith('test_') and fname not in ['test_example_inclusion', 'test_api_coverage', 'test_docs']:
            func()
