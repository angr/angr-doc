import angr

def main():
    p = angr.Project("r200", load_options={'auto_load_libs': False})
    ex = p.surveyors.Explorer(find=(0x400936, ), avoid=(0x400947,), enable_veritesting=True)
    ex.run()

    return ex.found[0].state.posix.dumps(0).strip('\0\n')

def test():
    assert main() == 'rotors'

if __name__ == '__main__':
    print main()
