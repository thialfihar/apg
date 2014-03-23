APG (Android Privacy Guard)
===========================

OpenPGP for Android.

I'd like to pick this up again, despite the awesome advances of the fork [OpenPGP-Keychain](https://github.com/openpgp-keychain/openpgp-keychain/). Those guys did a great job, but I differ in some of the implementation details and decisions, so I hope the projects can continue to benefit from each other.

APG definitely has some catching up to do. :)

## Build

### Requirements

* Android SDK 19.0.3
* Java 1.6

### Command line
```
> git submodule update --init --recursive
> ./gradlew build -Dandroid.sdk=$ANDROID_HOME
```
android.sdk is only needed for ProGuard. assembleDebug can be run without it.
Alternatively `android.sdk=...` can be put into `<project.dir>/gradle.properties` or `~/.gradle/gradle.properties`, then it won't be needed in the command.

### Travis CI Build Status

[![Build Status](https://travis-ci.org/thialfihar/apg.png?branch=master)](https://travis-ci.org/thialfihar/apg)
