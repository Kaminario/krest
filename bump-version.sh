#!/bin/bash

set -e 

ver=$1
if [[ "$ver" == "" ]]; then
	echo "usage: $0 <new version>"
	exit 1
fi

sed -i -r 's/^(__version__ = ")[0-9]+.[0-9]+.[0-9]+/\1'$ver'/' krest.py
sed -i -r 's/^(Version: +)[0-9]+\.[0-9]+\.[0-9]+/\1'$ver'/' krest.spec
sed -i -r 's/(version=")[0-9]+\.[0-9]+\.[0-9]+/\1'$ver'/' setup.py

git commit krest.py krest.spec setup.py -m "version bump to $ver"
git tag -a "v$ver" -m "v$ver"

git push
git push --tags

echo "Bumped version to $ver and tagged it in git"

