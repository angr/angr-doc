#!/bin/bash

rm crackme1.jar
(
cd crackme1_src
javac -classpath . crackme1/*.java
jar cfm ../crackme1.jar META-INF/MANIFEST.MF crackme1/*.class
)

# java -jar crackme1.jar
