import pkg_resources
import shutil
import sys
import os

if len(sys.argv) != 2:
    print "usage: {} [unicorn-win-core-root]".format(sys.argv[0])
    sys.exit()

dest = pkg_resources.resource_filename('unicorn', 'include')
if os.path.exists(dest):
    shutil.rmtree(dest)
shutil.copytree("{}{}{}".format(sys.argv[1], os.sep, 'include'), dest)
dest = pkg_resources.resource_filename('unicorn', 'lib')
shutil.copy("{}{}{}".format(sys.argv[1], os.sep, 'unicorn.lib'), dest)
