# Instructions for building packages for various distros

## Overview

We're using the [Tarantool Build scripts](https://github.com/tarantool/build) to generate a tar source file and then use docker to build and package the sources for various platforms.

## Automatic builds

Various packages should be automatically built and published to packagecloud.io on successful builds via travis. Merged PR requests should result in new builds.

## Local builds

For local builds, you'll need to have Docker installed. Then follow these steps from inside the ironssh base directory:

1. `git clone git@github.com:zmre/build.git`
2. `./build/build clean`
3. `git describe --long --always > VERSION`
3. `./build/build PRODUCT=ironssh centos7 fedora22 fedora23 fedora24 fedora-rawhide`

Use other platform identifiers as desired.  If all goes well, you'll find your packages under `build/root`

## Tagging for release

To get a new version number started, you need to make an annotated tag and push it to github (unless you're just building locally):

1. `git tag -a "x.y.z" -m "tag comment"`
2. `git push origin "x.y.z"
