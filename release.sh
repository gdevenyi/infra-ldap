#!/bin/bash

# Don't use uninitialized vars
set -o nounset
# Set strict umask
umask 077

# remove all temporary stuff
./clean.sh

# After here exit on any error
set -e

TOX_ENV="py$(python3 -c 'import sys ; print("%s%s" % (sys.version_info.major, sys.version_info.minor))')"

# first run the test suite isolated just to be sure
SLAPD_SLEEP="0.1" TMP="/tmp" tox -e "${TOX_ENV}"

# determine version numer
RELEASE=$(PYTHONPATH=infraldap python3 -c 'from __about__ import __version__ ; print(__version__)')

echo "Will tag and publish ${RELEASE} now..."

# push and tag the git repo
git push
git tag -s -m "release ${RELEASE}" "v${RELEASE}"
git push --tags

# build source distribution and push to PyPI
# (release defined in setup.cfg)
python3 setup.py \
  clean --all \
  sdist --formats=gztar
python3 -m twine upload -s "dist/slapdsock-${RELEASE}.tar.gz"
