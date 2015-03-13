The Cloud
===================
Angr is a very powerful tool however it also needs quite some processing power.
To make the developer's live easier, a class for executing analyses on multiple binaries at the same time in the cloud is included. Usage is discussed below.

Install
-------------
Currently the largescale class is not installed in the docker container by default.
To add it, simply checkout 
```
git@git.seclab.cs.ucsb.edu:angr/largescale.git
```
and either run ipython from inside this folder or symlink it to python's lib path.
Importing angr should now automatically pick it up and the startup info should be gone.


Loading binaries
-------------
The interface to Orgies is almost the same as that of a Project.

Run `o = angr.Orgy('<list of binaries')` to load binaries you want to run the analyses on. You can pass in the same parameters as in a Project, for example to resolve all dependent libraries you can use 
```python
    o = angr.Orgy(['/home/angr/httpd', '/home/angr/foo', 'home/angr/bar'], load_options={"auto_load_dependencies": True})
```
The list of binaries always have to be a full path name to either a binary or a folder and they need to be available on the worker's paths as well (duh)
It's also possible to automatically crawl for binaries in a folder by setting recursive to True:
```python
o = angr.Orgy('/home/angr/searchme', recursieve=True)
```
(Note that you don't have to pass a list, a single item works as well)

Be careful:
Local binaries will currently _not_ be transmitted to the cloud, only the path will be. So make sure you are using the path to a shared folder that is avaliable in the vlan 151. (Ideally on the trashcan)
Also you need to have the latest version of your local source code checked in into git, the script will make the cloud nodes to update to the same revision.

Load Options
-------------
You can pass the same options to Orgy as you would normally pass to Project.
If you want to pass different load options to different binaries it's possible using `bin_specific_options` or, easier, by creating multiple Orgies and then `Orgy.merge`ing them together.
```python
orgies = []
for filename, path, root in firmwares:
    firmware_root = find_firmware_root(path, root)
    orgies.append(angr.Orgy(filename, load_options={"custom_ld_path": firmware_root, "auto_load_libs": True, "ignore_missing_libs": True, "ignore_import_version_numbers": True}))
orgy = Orgy.merge(orgies)
orgy.analyses.CFG()
```

Analyses
-------------
Now to the interesting part: running Analyses. 
It works just like you are used to from Project, instead this time you don't get the Analysis object back, but instead a Generator for AnalysisResults for every Binary, containing  `binary, job, result, log, errors, named_errors`.
You can pass the analyses all the same parameters as you're used to from Project's p.analyses.
```python
for ar in o.analyses.CFG():
	print ar.result  # Currently nothing to see here.
```
At the time of writing, not all Analyses return results, you may want to write a wrapper for it.

Multi
-------------
Doing multiple analyses is cool, however we have to write a wrapper everytime we want to do more than one analysis in a row on a binary, right?
Of course not. 
The multi interface gives you the option to chain analyses that will be executed serially on the same worker using the same project instance. All results will be returned as a list of analysis results.
After finishing, you want to execute the multi instance using .execute()
```
m = o.multi()
m.CFG().VFG().DDG().BufferOverlap()
for result in m.execute():
	for ar in ars
	print "%s finished: %s" % (ar.job.analysis, ar.result)
```
You can pass any analysis all the same parameters as they accept using the normal Project p.analyses.

All analyses for one binary will run in the same project sequentially.

Advanced
-------------
-------------
This is for everybody that wants to mess with cloud nodes and workers.

Celery
-------------
Angr uses [Celery](http://www.celeryproject.org/) as the framework for everything cloud. 
On every cloudnode you'll have to start a docker worker with a single thread. 
This can be done using
```
celery -A angr.largescale.orgy worker -c1
```

The Cloud Setup
-------------
Currently, the cloud nodes operate on VLAN151.
They have internet access (currently needed for docker's install) over a caching squid3 proxy on the trashcan (10.151.0.1).
For celery, a mongodb runs on the trashcan and the rabbitmq queue runs on herrington, 10.151.0.9 (on port 5671 with SSL).
The cloud scripts will try to access git, so they need to have all important git certs set. Have a look at the script on
https://git.seclab.cs.ucsb.edu/gitlab/angr/largescale/blob/master/largescale/bootstrap_cloud.sh