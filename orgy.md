The Cloud
===================
Angr is a very powerful tool however it also needs quite some processing power.
To make the developer's live easier, a class for executing analyses on multiple binaries at the same time in the cloud is included. Usage is discussed below.

Celery
-------------
Angr uses [Celery](http://www.celeryproject.org/) as the framework for everything cloud. 
On whatever Docker instance you want to run the cloud on, you'll have to start a docker worker, somehow along the lines of
```
celery -A largescale worker -c10 --loglevel=INFO --autoreload
```
With -c being the number of workers and autoreload helping to import updated files automatically. (You'll still need to git pull eventually.)

Loading binaries
-------------
As soon as you got some workers running, you can run Orgies. The interface is similar to that of a Project.

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

Load Options
-------------
You can pass the same options to Orgy as you would normally pass to Project.
If you want to pass different load options to different binaries it's possible using `bin_specific_options` or easier by creating multiple Orgies and then `Orgy.merge` them together.
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
At the time of writing, no Analyses return results, you may still have to write a wrapper for it...

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