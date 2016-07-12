# Installing angr

angr is a python library, so it must be installed into your python environment before it can be used.
It is built for Python 2: Py3k support is feasible somewhere out in the future, but we are a little hesitant to make that commitment right now (pull requests welcome!).

We highly recommend using a [python virtual environment](https://virtualenvwrapper.readthedocs.org/en/latest/) to install and use angr.
Several of angr's dependencies (z3, pyvex) require libraries of native code that are forked from their originals, and if you already have libz3 or libVEX installed, you definitely don't want to overwrite the official shared objects with ours.
In general, don't expect support for problems arising from installing angr outside of a virtualenv.

## Dependencies

All of the python dependencies should be handled by pip and/or the setup.py scripts.
You will, however, need to build some C to get from here to the end, so you'll need a good build environment as well as the python development headers.
At some point in the dependency install process, you'll install the python library cffi, but (on linux, at least) it won't run unless you install your operating system's libffi package.

On Ubuntu, you will want: `sudo apt-get install python-dev libffi-dev build-essential virtualenvwrapper`

## Most Operating systems, all \*nix systems

`mkvirtualenv angr && pip install angr` should usually be sufficient to install angr in most cases, since angr is published on the Python Package Index.

Fish (shell) users can either use [virtualfish](https://github.com/adambrenecki/virtualfish) or the [virtualenv](https://pypi.python.org/pypi/virtualenv) package.<br>
`vf new angr && vf activate angr && pip install angr`

Failing that, you can install angr by installing the following repositories (and the dependencies listed in their requirements.txt files), in order, from https://github.com/angr:

- [claripy](https://github.com/angr/claripy)
- [archinfo](https://github.com/angr/archinfo)
- [pyvex](https://github.com/angr/pyvex)
- [cle](https://github.com/angr/cle)
- [simuvex](https://github.com/angr/simuvex)
- [angr](https://github.com/angr/angr)

## Mac OS X

Before you say `pip install angr`, you need to rebuild our fork of z3 with `pip install -I --no-use-wheel angr-only-z3-custom`.

## Windows

You cannot install angr from pip on windows.
You must install all of its components individually.

Capstone is difficult to install on windows.
You might need to manually specify a wheel to install, but sometimes it installs under a name different from "capstone", so if that happens you want to just remove capstone from the requirements.txt files in angr and archinfo.

Z3 might compile on windows if you have a l33t enough build environment.
If this isn't the case for you, you should download a wheel from somewhere on the Internet.
One location for pre-built Windows wheel files is <https://github.com/Owlz/angr-Windows>.

If you build z3 from source, make sure you're using the unstable branch of z3, which includes floating point support.
In addition, make sure to have `Z3PATH=path/to/libz3.dll` in your environment.

## Development install

We created a repo with scripts to make life easier for angr developers.
You can set up angr in development mode by doing:

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
sudo docker run -it angr
```

Synchronization of files in and out of docker is left as an exercise to the user (hint: check out `docker -v`).

# Troubleshooting

## libgomp.so.1: version GOMP_4.0 not found
This error represents an incompatibility between the pre-compiled version of `angr-only-z3-custom` and the installed version of `libgomp`. A Z3 recompile is required. You can do this by executing:

```bash
pip install -I --no-use-wheel angr-only-z3-custom
```

## Can't import mulpyplexer
There are sometimes issues with installing mulpyplexer. Doing `pip install --upgrade 'git+https://github.com/zardus/mulpyplexer'` should fix this.

## Can't import angr because of capstone
Sometimes capstone isn't installed correctly for use by angr. There's a good chance just reinstalling capstone will solve this issue:

```bash
pip install -I --no-use-wheel capstone
```

## ImportError due to failure in loading capstone while importing angr
There's a known [issue](https://github.com/aquynh/capstone/issues/445) in installing capstone_3.0.4 using pip in virtualenv/virtualenvwrapper environment. Several users have further reported to be affected by the same bug in native Python installation, too. (See the discussion in Github bug report).

In virtual environment, if capstone Python files are installed in `/home/<username>/.virtualenvs/<virtualenv>/lib/python2.7/site-packages/capstone/*.py(c)`, capstone library file will be found in `/home/<username>/.virtualenvs/<virtualenv>/lib/python2.7/site-packages/home/<username>/.virtualenvs/<virtualenv>/lib/python2.7/site-packages/capstone/libcapstone.so`

In native environment, if capstone Python files are installed in `/usr/local/lib/python2.7/dist-packages/capstone/*.py(c)`, capstone library file will be found in `/usr/local/lib/python2.7/dist-packages/usr/lib/python2.7/dist-packages/capstone/libcapstone.so`

Moving `libcapstone.so` to the same directory as that of Python files will fix the problem.

## Claripy and z3
Z3 is a bit weird to compile. Sometimes it just completely fails to build for
no reason, saying that it can't create some object file because some file or
directory doesn't exist. Just retry the build:

```bash
pip install -I --no-use-wheel angr-only-z3-custom
```

## No such file or directory: 'pyvex_c'

Are you running 12.04? If so, please upgrade!

You can also try upgrading pip (`pip install -U pip`), which might solve the issue.
