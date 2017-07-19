import angr
import logging

def main():
    p = angr.Project("r200", load_options={'auto_load_libs': False})
    sm = p.factory.simgr(veritesting=True)
#   ex = p.surveyors.Explorer(find=(0x400936, ), avoid=(0x400947,), enable_veritesting=True)
#   angr.surveyors.explorer.l.setLevel(logging.DEBUG)
#   ex.run()
    angr.manager.l.setLevel(logging.DEBUG)
    sm.explore(find=(0x400936), avoid=(0x400947))

    return sm.found[0].posix.dumps(0).strip('\0\n')
#   return ex.found[0].posix.dumps(0).strip('\0\n')

def test():
    assert main() == 'rotors'

if __name__ == '__main__':
    print main()
