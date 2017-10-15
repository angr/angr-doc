# 安装 angr

angr 是一个 Python 库，所以必须被安装在 Python 环境中才可以使用。目前 angr 使用 Python 2，对 Python 3 的支持也许将来会实现，我们很犹豫现在就要做出如此承诺（不过我们欢迎您提交 PR！）

我们强烈推荐您使用 [Python 虚拟环境](https://virtualenvwrapper.readthedocs.org/en/latest/) 来安装、使用 angr。因为 angr 的一些依赖（Z3,pyvex）需要的库经过我们的修改了，如果您早已安装了 libz3 或 libVEX，您一定不想让我们的库覆盖官方的库。通常来说，在虚拟环境之外安装的 angr 出现问题，不要期望会得到解答。

### 依赖

通常，所有 Python 的依赖都应该由 pip 或 setup.py 处理。然而，当你想从头到尾构建一个工具的时候，你最好可以构建一个和开发者相同的环境。在你进行依赖安装过程中时，也许你在安装 Python 库 cffi，但是（至少在 linux 上），除非你安装了操作系统的 libffi 包，否则你不可能安装成功。

Ubuntu 需要执行 `sudo apt-get install python-dev libffi-dev build-essential virtualenvwrapper`，如果你想试用 angr-management 的话，还需要执行 `sudo apt-get install libqt4-dev graphviz-dev`

### 大多数操作系统，所有 \*nix 操作系统

`mkvirtualenv angr && pip install angr` 绝大多数情况下就可以成功安装 angr 了，因为 angr 是在 Python Package Index 上发布的库。

Fish (shell) 用户可以使用 [virtualfish](https://github.com/adambrenecki/virtualfish) 或者 [virtualenv](https://pypi.python.org/pypi/virtualenv) 来执行 `vf new angr && vf activate angr && pip install angr`

或者，您可以通过安装以下组件（以及它们在 requirements.txt 中列出的依赖项）来安装 [angr](https://github.com/angr:)

- [claripy](https://github.com/angr/claripy)
- [archinfo](https://github.com/angr/archinfo)
- [pyvex](https://github.com/angr/pyvex)
- [cle](https://github.com/angr/cle)
- [angr](https://github.com/angr/angr)

### Mac OS X

`pip install angr` 应该是可以的，但仍然有一些注意事项

如果用 Clang 不幸遇到构建失败，请试试 GCC

```bash
brew install gcc
env CC=/usr/local/bin/gcc-6 pip install angr
```

安装 angr 后，您需要修正一些共享库的路径为 angr 自带的库路径

```bash
BASEDIR=/usr/local/lib/python2.7/site-packages
# If you don't know where your site-packages folder is, use this to find them:
python2 -c "import site; print(site.getsitepackages())"

install_name_tool -change libunicorn.1.dylib "$BASEDIR"/unicorn/lib/libunicorn.dylib "$BASEDIR"/angr/lib/angr_native.dylib
install_name_tool -change libpyvex.dylib "$BASEDIR"/pyvex/lib/libpyvex.dylib "$BASEDIR"/angr/lib/angr_native.dylib
```

### Windows

angr  _也许可以_ 使用 pip 在 Windows 上安装成功，你可以通过 visual studio 来进行构建

Capstone 很难安装在 Windows 上，您也许需要手动安装 wheel 版，但有时名字会发生改变，和 capstone 略有出入，此时您只需要在 angr 和 archinfo 的 requirements.txt 中移除 capstone 即可

# 开发者安装

我们创建了一个方便 angr 开发者的仓库，您可以通过以下方式在开发模式下运行 angr：

```bash
git clone git@github.com:angr/angr-dev.git
cd angr-dev
mkvirtualenv angr
./setup.sh
```

这将克隆整个仓库并以可编辑模式进行安装，`setup.sh` 甚至可以为您创建一个 PyPy virtualenv 虚拟环境，从而显著提高性能表现并降低内存使用

您可以分支、编辑、重编译任何一个模块， 并在虚拟环境中进行测试

## Docker 安装

为方便起见，我们上传了一个 Docker 镜像，在绝大多数情况下（99%）它都可以正常工作。您可以通过 docker 来进行安装:

```bash
# install docker
curl -sSL https://get.docker.com/ | sudo sh

# pull the docker image
sudo docker pull angr/angr

# run it
sudo docker run -it angr/angr
```

Docker 的文件同步留给使用者进行练习（提示：check out `docker -v`）

### 修改 angr 容器

您可能会发现需要通过 apt 来安装其他软件包，容器的 vanilla 版没有安装 sudo 包，这意味着容器中的默认用户没有权限来升级、安装其他包

要绕过这个限制，请使用以下 docker 命令来授予 root 权限：

```bash
# assuming the docker container is running 
# with the name "angr" and the instance is
# running in the background.
docker exec -ti -u root angr bash
```

# 故障排除

## libgomp.so.1: version GOMP_4.0 not found, or other z3 issues

这是一个典型错误，表示预编译版本 `angr-only-z3-custom` 和 `libgomp` 的已安装版本不兼容。需要对 Z3 进行重编译，可以使用以下命令：

```bash
pip install -I --no-use-wheel z3-solver
```

## Can't import angr because of capstone

有时候 capstone 安装不正确，也是一个重新构建 capstone 的好机会，确保使用预发行版本（capstone 的版本发行很奇怪）就可以解决这个问题

```bash
pip install -I --pre --no-use-wheel capstone
```

如果没能解决，可能是一个在 virtualenv/virtualenvwrapper 虚拟环境中使用 pip 安装 capstone_3.0.4 时已知的 [issue](https://github.com/aquynh/capstone/issues/445)，有一些用户报告在非虚拟环境中安装时也遇到了相同的错误（请参看 GitHub 错误报告中的讨论）

在虚拟环境中，如果 capstone 被安装在 `/home/<username>/.virtualenvs/<virtualenv>/lib/python2.7/site-packages/capstone/*.py(c)` 中，capstone 的库文件将会在 `/home/<username>/.virtualenvs/<virtualenv>/lib/python2.7/site-packages/home/<username>/.virtualenvs/<virtualenv>/lib/python2.7/site-packages/capstone/libcapstone.so`

在非虚拟环境中，如果 capstone 被安装在 `/usr/local/lib/python2.7/dist-packages/capstone/*.py(c)`中，capstone 的库文件将会在 `/usr/local/lib/python2.7/dist-packages/usr/lib/python2.7/dist-packages/capstone/libcapstone.so`

移动 `libcapstone.so` 到和 python 文件相同的目录即可解决这个问题

## No such file or directory: 'pyvex_c'

您正在使用的环境是 Ubuntu 12.04 吗？如果是，请停止使用这款发布超过五年的操作系统吧！升级是免费的！

您也可以尝试升级 pip（pip install -U pip），也许可能会解决该问题

## AttributeError: 'FFI' object has no attribute 'unpack'

您的 `cffi` Python 模块过时了，angr 需要至少 1.7 版本的 cffi。试着执行 `pip install --upgrade cffi`。如果问题仍然存在，请确保系统中预安装旧版本的 cffi 都被清除了，否则 pip 可能会拒绝卸载
如果您使用 pypy 作为 Python 的虚拟环境，请确保您使用的是最新版本的 pypy，因为其中包含了一个 pip 是不会为它升级的 cffi 的旧版本
