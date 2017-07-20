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

After installing angr, you will need to fix some shared libraries paths for simuvex.

```bash
BASEDIR=/usr/local/lib/python2.7/site-packages
# If you don't know where your site-packages folder is, use this to find them:
python2 -c "import site; print(site.getsitepackages())"

install_name_tool -change libunicorn.1.dylib "$BASEDIR"/unicorn/lib/libunicorn.dylib "$BASEDIR"/simuvex/lib/sim_unicorn.dylib
install_name_tool -change libpyvex.dylib "$BASEDIR"/pyvex/lib/libpyvex.dylib "$BASEDIR"/simuvex/lib/sim_unicorn.dylib
```

### Windows

angr can _probably_ be installed from pip on Windows, given that you're in a shell with the visual studio build tools loaded.

Capstone is difficult to install on windows. You might need to manually specify a wheel to install, but sometimes it installs under a name different from "capstone", so if that happens you want to just remove capstone from the requirements.txt files in angr and archinfo.

# Development install

We created a repo with scripts to make life easier for angr developers.
You can set up angr in development mode by running:

```bash
git clone https://github.com/angr/angr-dev
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

This specific error represents an incompatibility between the pre-compiled version of `angr-only-z3-custom` and the installed version of `libgomp`. A Z3 recompile is required. You can do this by executing:

```bash
pip install -I --no-use-wheel z3-solver
```

## Can't import angr because of capstone

Sometimes capstone isn't installed correctly for use by angr. There's a good chance just rebuilding capstone, making sure to use the pre-release version (capstone's distribution is very strange) will solve this issue:

```bash
pip install -I --pre --no-use-wheel capstone
```

If this doesn't work, there's a known [issue](https://github.com/aquynh/capstone/issues/445) in installing capstone_3.0.4 using pip in virtualenv/virtualenvwrapper environment. Several users have further reported to be affected by the same bug in native Python installation, too. (See the discussion in Github bug report).

In virtual environment, if capstone Python files are installed in `/home/<username>/.virtualenvs/<virtualenv>/lib/python2.7/site-packages/capstone/*.py(c)`, capstone library file will be found in `/home/<username>/.virtualenvs/<virtualenv>/lib/python2.7/site-packages/home/<username>/.virtualenvs/<virtualenv>/lib/python2.7/site-packages/capstone/libcapstone.so`

In native environment, if capstone Python files are installed in `/usr/local/lib/python2.7/dist-packages/capstone/*.py(c)`, capstone library file will be found in `/usr/local/lib/python2.7/dist-packages/usr/lib/python2.7/dist-packages/capstone/libcapstone.so`

Moving `libcapstone.so` to the same directory as that of Python files will fix the problem.

## No such file or directory: 'pyvex_c'

Are you running Ubuntu 12.04? If so, please stop using a 5 year old operating system! Upgrading is free!

You can also try upgrading pip (`pip install -U pip`), which might solve the issue.
