#!/bin/bash

# cp -a   ../../../../eclipse_workspace/simple3/src/** simple3_src

rm simple3.jar
(
cd simple3_src
javac -classpath . simple3/*.java
jar cfm ../simple3.jar META-INF/MANIFEST.MF simple3/*.class
)

# java -jar simple3.jar
