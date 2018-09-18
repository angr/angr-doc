import subprocess
import os

def _path(d):
    return os.path.join(os.path.dirname(__file__), '..', d)

def test_api_coverage():
    missing = []
    exclude = ['angr.tablespecs', 'angr.service', 'pyvex.vex_ffi', 'claripy.backends.remotetasks', 'claripy.backends.backendremote']
    exclude_prefix = ['angr.procedures', 'angr.analyses.identifier', 'angr.misc', 'angr.surveyors', 'angr.engines.vex', 'claripy.utils']
    for module in ['angr', 'claripy', 'cle', 'pyvex', 'archinfo']:
        docs_file = _path('api-doc/source/%s.rst' % module)
        module_dir = _path('../%s/%s' % (module, module))
        module_list = subprocess.check_output(['find', '.', '-name', '*.py'], cwd=module_dir).split()
        api_list = [x.split()[-1] for x in open(docs_file).readlines() if 'automodule' in x]
        for partial in module_list:
            full = module + '.' + partial[2:-3].decode().replace('/', '.')
            if full.endswith('.__init__'):
                full = full[:-9]

            if full not in api_list and full not in exclude:
                for ep in exclude_prefix:
                    if full.startswith(ep):
                        break
                else:
                    missing.append(full)

    if missing:
        raise Exception("The following modules are not represented in the api docs:\n" + '\n'.join(missing))

def test_lint_docstrings():
    subprocess.check_call('make clean', shell=True, cwd=_path('api-doc'))
    p = subprocess.Popen('make html', shell=True, cwd=_path('api-doc'), stderr=subprocess.PIPE)
    _, stderr = p.communicate()

    # Filter the deprecation warning from the cryptography package
    if stderr:
        stderr_lines = stderr.split(b"\n")
        stderr = b"\n".join(l for l in stderr_lines if b'MIPS instruction groups' not in l)

    if stderr:
<<<<<<< HEAD
        raise Exception("The following warnings were generated while building the API documentation:\n\n%s" % stderr)
=======
        raise Exception("The following warnings were generated while building the API documentation:\n\n%s" % stderr.decode())
>>>>>>> f31a0a6912b60764bb8700ec9b6ea792f256da33

if __name__ == '__main__':
    test_api_coverage()
    test_lint_docstrings()
