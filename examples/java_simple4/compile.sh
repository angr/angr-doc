#!/bin/bash

rm simple4.jar
(
cd simple4_src
javac -classpath . simple4/*.java
jar cfm ../simple4.jar META-INF/MANIFEST.MF simple4/*.class
)

# java -jar simple4.jar
