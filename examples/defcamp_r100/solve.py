import angr

p = angr.Project("r100", load_options={'auto_load_libs': False})
ex = p.surveyors.Explorer(find=(0x400844, ), avoid=(0x400855,))
ex.run()

print "Flag:", ex.found[0].state.posix.dumps(0)

# Flag: Code_Talkers

