import angr

p = angr.Project("r200", load_options={'auto_load_libs': False})
ex = p.surveyors.Explorer(find=(0x400936, ), avoid=(0x400947,), enable_veritesting=True)
ex.run()

print "Flag:", ex.found[0].state.posix.dumps(0)

# Flag: rotors

