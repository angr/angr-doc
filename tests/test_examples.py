import os
import sys
import subprocess
from importlib import reload

from nose.plugins.attrib import attr
from flaky import flaky

def _path(d):
    return os.path.join(os.path.dirname(__file__), '..', d)

def exampletest_single(example_dir):
    init_pwd = os.getcwd()
    os.chdir(_path('examples/') + example_dir)
    print(os.getcwd())
    sys.path.append(os.getcwd())
    try:
        s = __import__('solve')
        s = reload(s)
        s.test()
    finally:
        sys.path.pop()
        os.chdir(init_pwd)

## BEGIN EXAMPLE TESTS
#@attr(speed='slow')
#def test_9447_nobranch(): exampletest_single('9447_nobranch') # hours? also broken right now
def test_0ctf_trace():  exampletest_single('0ctf_trace')
def test_ais3_crackme(): exampletest_single('ais3_crackme')
@attr(speed='slow')
def test_asisctffinals2015_fake(): exampletest_single('asisctffinals2015_fake')
def test_asisctffinals2015_license(): exampletest_single('asisctffinals2015_license')
@attr(speed='slow')
def test_CADET_00001(): exampletest_single('CADET_00001') # 2m
@attr(speed='slow')
def test_cmu_binary_bomb(): exampletest_single('cmu_binary_bomb') # 3m
@attr(speed='slow')
def test_csaw_wyvern(): exampletest_single('csaw_wyvern') # 3m40s
@attr(speed='slow')
def test_b01lersctf(): exampletest_single('b01lersctf2020_little_engine')
def test_defcamp_r100(): exampletest_single('defcamp_r100')
#def test_defcamp_r200(): exampletest_single('defcamp_r200') # broken..?
def test_ekopartyctf2015_rev100(): exampletest_single('ekopartyctf2015_rev100')
def test_ekopartyctf2016_rev250(): exampletest_single('ekopartyctf2016_rev250')
def test_ekopartyctf2016_sokohashv2(): exampletest_single('ekopartyctf2016_sokohashv2')
def test_fauxware(): exampletest_single('fauxware')
def test_flareon2015_10(): exampletest_single('flareon2015_10')
def test_flareon2015_2(): exampletest_single('flareon2015_2')
@attr(speed='slow')
def test_flareon2015_5(): exampletest_single('flareon2015_5') # 2m11s
@attr(speed='slow')
def test_hitcon2017_sakura(): exampletest_single('hitcon2017_sakura') # 6m
def test_google2016_unbreakable_0(): exampletest_single('google2016_unbreakable_0')
def test_google2016_unbreakable_1(): exampletest_single('google2016_unbreakable_1')
def test_grub(): exampletest_single('grub')
def test_mma_howtouse(): exampletest_single('mma_howtouse')
@attr(speed='slow')
def test_mma_simplehash(): exampletest_single('mma_simplehash') # ~hour
def test_securityfest_fairlight(): exampletest_single('securityfest_fairlight')
def test_strcpy_find(): exampletest_single('strcpy_find')
def test_whitehat_crypto400(): exampletest_single('whitehat_crypto400')
def test_whitehatvn2015_re400(): exampletest_single('whitehatvn2015_re400')
@attr(speed='slow')
@flaky(max_runs=3, min_passes=1)
def test_secconquals2016_ropsynth(): exampletest_single('secconquals2016_ropsynth') # technically not that slow but impossible to run under multiprocessing
@attr(speed='slow')
def test_0ctf_momo_3(): exampletest_single('0ctf_momo_3') # 16m
def test_defcon2016quals_baby_re(): exampletest_single('defcon2016quals_baby-re')
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
def test_angry_reverser(): exampletest_single('hackcon2016_angry-reverser')
def test_sharif7(): exampletest_single('sharif7_rev50')
def test_angrybird(): exampletest_single('codegate_2017-angrybird')
@attr(speed='slow')
def test_mbrainfuzz(): exampletest_single('secuinside2016mbrainfuzz') # 1m46s
def test_unmapped_analysis(): exampletest_single('unmapped_analysis')
@attr(speed='slow')
def test_zwiebel(): exampletest_single('tumctf2016_zwiebel') # ~45m
def test_csgames2018(): exampletest_single('csgames2018')
def test_java_crackme1(): exampletest_single('java_crackme1')
def test_java_simple3(): exampletest_single('java_simple3')
def test_java_simple4(): exampletest_single('java_simple4')
def test_ictf2017_javaisnotfun(): exampletest_single('ictf2017_javaisnotfun')
def test_java_androidnative1(): exampletest_single('java_androidnative1')
@attr(speed='slow')
def test_defcon2019quals_veryandroidoso(): exampletest_single('defcon2019quals_veryandroidoso')
## END EXAMPLE TESTS

def test_example_inclusion():
    to_test = subprocess.check_output(['/bin/bash', '-c', 'for c in $(find -name solve.py | cut -c 3-); do echo ${c%/solve.py}; done'], cwd=_path('examples')).decode()
    if __file__.endswith('.pyc'):
        sourcefile = __file__[:-1]
    else:
        sourcefile = __file__
    with open(sourcefile, 'r', encoding='utf-8') as fp:
        test_source = fp.read()
    example_tests = test_source[test_source.find('## BEGIN EXAMPLE TESTS'):test_source.find('## END EXAMPLE TESTS')]

    missing = []
    for line in to_test.strip().split('\n'):
        if ("exampletest_single('%s')" % line) not in example_tests:
            missing.append(line)
    if missing:
        raise Exception("The following examples are not represented in the test corpus:\n" + '\n'.join(missing))

if __name__ == '__main__':
    test_example_inclusion()

    for fname, func in globals().items():
        if callable(func) and fname.startswith('test_') and fname != 'test_example_inclusion':
            func()
