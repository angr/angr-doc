#!/usr/bin/python
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http:#www.gnu.org/licenses/>.
# </copyright>
# <author>Jonathan Racicot</author>
# <email>cyberrecce@gmail.com</email>
# <twitter>@cyberrecce</twitter>
# <date>2017-01-12</date>
# <url>https://github.com/infectedpacket</url>
# <url>http://thecyberrecce.net</url>
# <summary>
#  This solver uses Angr to solve the SharifCTF 7 first reverse engineering
#  problem. Note that Angr is absolutely not required to do this, but I find
#  it a good example on how to start using Angr.
#
#  This binary is simple and doesn't actually require to solve
#  anything, we just need to reach a certain point in the execution
#  and retrieve a string from memory.
#
#  The mechanism here is that this binary transforms a md5 hash stored internally
#  and writes it into a file in the /tmp/ directory. Before exiting, it deletes
#  the file.
#
#  Therefore, we use Angr to launch the execution and stop it just before the call
#  deleting the file. We then extract the de-obfuscated string in memory to find
#  the flag.
# </summary>
#//////////////////////////////////////////////////////////////////////////////
#
#//////////////////////////////////////////////////////////////////////////////
# Imports Statements
#
import os
import argparse
import angr
#
#//////////////////////////////////////////////////////////////////////////////
# Program Information
#
PROGRAM_NAME = "solve.py"
PROGRAM_DESC = "Solves SharifCTF 7 Rev50 Challenge using Angr."
PROGRAM_USAGE = "%(prog)s"
__version_info__ = ('0', '1', '0')
__version__ = '.'.join(__version_info__)
#
#//////////////////////////////////////////////////////////////////////////////
# Argument Parser Declaration
#
usage = PROGRAM_USAGE
parser = argparse.ArgumentParser(
    usage=usage,
    prog=PROGRAM_NAME,
    description=PROGRAM_DESC)
io_options = parser.add_argument_group("I/O Options", "Input and output data options.")
io_options.add_argument("-f", "--file",
    dest="input",
    required=True,
    help="The Rev50 binary from SharifCTF 7")
#
#//////////////////////////////////////////////////////////////////////////////
# Core functions
#
FLAG = "SharifCTF{b70c59275fcfa8aebf2d5911223c6589}"
FLAG_STR = "SharifCTF{????????????????????????????????}"
#
def solve(_file):

    # The de-obfuscated flag is stored at this address:
    flag_addr = 0x6010e0

    # We set the srop address before the program deletes
    # the file file where the de-obfuscated flag is stored.
    stop_addr = 0x4008c8

    # Creates a Angr project. Always needed and always the
    # first line
    project = angr.Project(_file, load_options={"auto_load_libs": False})

    # We then need to define a start state for the execution.
    # The initial state usually contains the arguments given
    # to the program or can be a blank state with a start address.
    # In this case, this program doesn't need any special arg other
    # than the name of the program (as in any program, e.g. argv[0])
    argv = [project.filename]
    state = project.factory.entry_state(args=argv)

    # Now, Angr will start to execute the binary from this initial state
    # and explore many state until it reaches a certain condition. In this
    # case, we want to run until we reached our stop_addr.
    sm = project.factory.simulation_manager(state)
    sm.explore(find=stop_addr)

    # At this point, the first active path reached our stop address
    # and therefore, the de-obfuscated string is in memory. So we will
    # retrieve the 43 bytes (e.g. len(flag)) at flag_addr
    solve_var = sm.found[0].memory.load(flag_addr, len(FLAG_STR))
    # and convert it into a string:
    solved_flag = sm.found[0].solver.eval(solve_var, cast_to=str)

    return solved_flag

#
#//////////////////////////////////////////////////////////////////////////////
# Main
#
def test():
    challenge = os.path.join(os.getcwd(), "getit")
    assert solve(challenge) == FLAG

def main(_args):
    print solve(_args.input)

#
#//////////////////////////////////////////////////////////////////////////////
# Launcher
#
if __name__ == "__main__":
    args = parser.parse_args()
    main(args)
#
#//////////////////////////////////////////////////////////////////////////////
