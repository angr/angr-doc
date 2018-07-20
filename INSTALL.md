# Installing angr

angr is a python library, so it must be installed into your python environment before it can be used. It is built for Python 2: Py3k support is feasible somewhere out in the future, but we are a little hesitant to make that commitment right now (pull requests welcome!).

We highly recommend using a [python virtual environment](https://virtualenvwrapper.readthedocs.org/en/latest/) to install and use angr. Several of angr's dependencies (z3, pyvex) require libraries of native code that are forked from their originals, and if you already have libz3 or libVEX installed, you definitely don't want to overwrite the official shared objects with ours. In general, don't expect support for problems arising from installing angr outside of a virtualenv.

### Dependencies

All of the python dependencies should be handled by pip and/or the setup.py scripts. You will, however, need to build some C to get from here to the end, so you'll need a good build environment as well as the python development headers. At some point in the dependency install process, you'll install the python library cffi, but (on linux, at least) it won't run unless you install your operating system's libffi package.

On Ubuntu, you will want: `sudo apt-get install python-dev libffi-dev build-essential virtualenvwrapper`. If you are trying out angr-management, you will need `sudo apt-get install libqt4-dev graphviz-dev`.

### Most Operating systems, all \*nix systems

`mkvirtualenv angr && pip install angr` should usually be sufficient to install angr in most cases, since angr is published on the Python Package Index.

Fish (shell) users can either use [virtualfish](https://github.com/adambrenecki/virtualfish) or the [virtualenv](https://pypi.python.org/pypi/virtualenv) package: `vf new angr && vf activate angr && pip install angr`

Failing that, you can install angr by installing the following repositories (and the dependencies listed in their requirements.txt files), in order, from https://github.com/angr:

- [claripy](https://github.com/angr/claripy)
- [archinfo](https://github.com/angr/archinfo)
- [pyvex](https://github.com/angr/pyvex)
- [cle](https://github.com/angr/cle)
- [angr](https://github.com/angr/angr)

### Mac OS X

`pip install angr` should work, but there are some caveats.

If you're unlucky and run into a broken build script with Clang, try using GCC.

```bash
brew install gcc
env CC=/usr/local/bin/gcc-6 pip install angr
```

After installing angr, you will need to fix some shared library paths for the angr native libraries.
Activate your virtual env and execute the following lines. [A script](https://github.com/angr/angr-dev/blob/master/fix_macOS.sh) is provided in the angr-dev repo.

```bash
PYVEX=`python2 -c 'import pyvex; print pyvex.__path__[0]'`
UNICORN=`python2 -c 'import unicorn; print unicorn.__path__[0]'`
ANGR=`python2 -c 'import logging; logging.basicConfig(level=logging.CRITICAL); import angr; print angr.__path__[0]'`

install_name_tool -change libunicorn.1.dylib "$UNICORN"/lib/libunicorn.dylib "$ANGR"/lib/angr_native.dylib
install_name_tool -change libpyvex.dylib "$PYVEX"/lib/libpyvex.dylib "$ANGR"/lib/angr_native.dylib
```

### Windows

angr can _probably_ be installed from pip on Windows, given that you're in a shell with the visual studio build tools loaded.

Capstone is difficult to install on windows. You might need to manually specify a wheel to install, but sometimes it installs under a name different from "capstone", so if that happens you want to just remove capstone from the requirements.txt files in angr and archinfo.

# Development install

We created a repo with scripts to make life easier for angr developers.
You can set up angr in development mode by running:

```bash
git clone git@github.com:angr/angr-dev.git
cd angr-dev
mkvirtualenv angr
./setup.sh
```

This clones all of the repositories and installs them in editable mode.
`setup.sh` can even create a PyPy virtualenv for you, resulting in significantly faster performance and lower memory usage.

You can branch/edit/recompile the various modules in-place, and it will automatically reflect in your virtual environment.

## Docker install

For convenience, we ship a Docker image that is 99% guaranteed to work.
You can install via docker by doing:

```bash
# install docker
curl -sSL https://get.docker.com/ | sudo sh

# pull the docker image
sudo docker pull angr/angr

# run it
sudo docker run -it angr/angr
```

Synchronization of files in and out of docker is left as an exercise to the user (hint: check out `docker -v`).

### Modifying the angr container

You might find yourself needing to install additional packages via apt. The vanilla version of the container does not have the sudo package installed, which means the default user in the container cannot escalate privilege to install additional packages. 

To over come this hurdle, use the following docker command to grant yourself root access:

```bash
# assuming the docker container is running 
# with the name "angr" and the instance is
# running in the background.
docker exec -ti -u root angr bash
```

# Troubleshooting

## libgomp.so.1: version GOMP_4.0 not found, or other z3 issues

This specific error represents an incompatibility between the pre-compiled version of libz3.so and the installed version of `libgomp`. A Z3 recompile is required. You can do this by executing:

```bash
pip install -I --no-binary z3-solver z3-solver
```

## No such file or directory: 'pyvex_c'

Are you running Ubuntu 12.04? If so, please stop using a 5 year old operating system! Upgrading is free!

You can also try upgrading pip (`pip install -U pip`), which might solve the issue.

## AttributeError: 'FFI' object has no attribute 'unpack'

You have an outdated version of the `cffi` Python module.  angr now requires at least version 1.7 of cffi.
Try `pip install --upgrade cffi`.  If the problem persists, make sure your operating system hasn't pre-installed an old version of cffi, which pip may refuse to uninstall.
If you're using a Python virtual environment with the pypy interpreter, ensure you have a recent version of pypy, as it includes a version of cffi which pip will not upgrade.
