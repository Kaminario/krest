#!/bin/bash

#
# (c) 2015 Kaminario Technologies, Ltd.
#
# This software is licensed solely under the terms of the Apache 2.0 license,
# the text of which is available at http://www.apache.org/licenses/LICENSE-2.0.
# All disclaimers and limitations of liability set forth in the Apache 2.0 license apply.
#

set -e

tag=$1
if [[ "$tag" == "" ]]; then
	echo "usage: $0 <tagname>"
	exit 1
fi
git archive --prefix=krest-$tag/ --format=tar v$tag | gzip
