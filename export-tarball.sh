#!/bin/bash

set -e

tag=$1
if [[ "$tag" == "" ]]; then
	echo "usage: $0 <tagname>"
	exit 1
fi
git archive --prefix=krest-$tag/ --format=tar v$tag | gzip
