#!/bin/bash

rm androidnative1.apk
(
    cd app
    ./gradlew clean
    ./gradlew app:assembleDebug
    cp app/build/outputs/apk/debug/app-debug.apk ../androidnative1.apk
)
