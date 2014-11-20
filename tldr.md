TL;DR
===================

This is the **TL;DR** version to use `Angr` without understanding internals.

Install Docker
-------------
First, **install Docker**, download the `angr_docker` container, build it, but don't just use it.
Instead, **check out all angr git repos in a local folder** outside the docker container. Link them inside the docker container using the -v option and replace every project inside /home/angr/angr with the git projects. 
Why do you want to do this? For now, you'll most likely be using the `dev` branches of most git repos, since they will have the recent fixes. Once you restart docker, all changes inside the container are gone - you'd have to branch all git repos again. Also your own changes wouldn't stick during reboots.

Loading a Binary
-------------
After you installed Dockr and mapped local folders, you should have a terminal running a virtual environment called angr running inside the docker container. It's wise to use `tmux` here.
To test Angr on some binary, cd to the directory that contains the binary to analyze and fire up `ipython`.
Inside ipython, make heavy use of tab completion! It completes paths and filenames and shows you available functions.
Run `p = angr.Project('<name of binary')` to load the binary. Alternatively, you can try to resolve all dependent libraries using 

    p = angr.Project('httpd', load_options={"auto_load_dependencies": True})

You can also exclude some binaries from loading, see the loader docs for further information.

Interesting information about the binary is now accessible in `p.main_binary`, for example `deps`, the list of imported libs, `memory`, `symbols` and others. Make heavy use of the tabbing feature of ipython to see available functions and options here!

Analyses
-------------
There are a lot of analyses inside Angr. The available analyses can be found inside `angr/angr/analyses`. They can be run using the `p.analyze` function with the class name as String. Creating the CFG for example can be done using `cfg = p.analyze("CFG")` . Some analyses will instead export a `__name__`  that should be used to run them.


Surveyors
-------------
Surveyors are used to execute code. The commented classes can be found inside `angr/angr/surveyors`.
Just like the Analyses, they can be run using `p.survey`.
The `Slicecutor` runs a program slice, the `Executor` the whole program, ...