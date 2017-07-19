import angr

def main():
    p = angr.Project("r100", load_options={'auto_load_libs': False})
    ex = p.surveyors.Explorer(find=(0x400844, ), avoid=(0x400855,))
    ex.run()

    return ex.found[0].posix.dumps(0).strip('\0\n')

def test():
    assert main() == 'Code_Talkers'

if __name__ == '__main__':
    print main()
