#!/bin/sh

python3 setup.py clean --all
rm -r MANIFEST .coverage dist/infraldap* build/* *.egg-info .tox .eggs docs/.build/*
rm infraldap/*.py? tests/*.py? *.py?
find -name __pycache__ | xargs -n1 -iname rm -r name
rm -r slapdtest-[0-9]*
