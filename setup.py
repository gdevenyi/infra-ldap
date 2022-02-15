# -*- coding: ascii -*-
"""
package/install infraldap
"""

import sys
import os
from setuptools import setup, find_packages

PYPI_NAME = 'infra-ldap'
PYMOD_NAME = 'infraldap'

BASEDIR = os.path.dirname(os.path.realpath(__file__))

sys.path.insert(0, os.path.join(BASEDIR, PYMOD_NAME))
import __about__

setup(
    name=PYPI_NAME,
    license=__about__.__license__,
    version=__about__.__version__,
    description='DHCP/DNS/LDAP tools',
    author=__about__.__author__,
    author_email=__about__.__mail__,
    maintainer=__about__.__author__,
    maintainer_email=__about__.__mail__,
    url='https://code.stroeder.com/ldap/%s' % (PYPI_NAME,),
    download_url='https://pypi.python.org/pypi/%s/' % (PYPI_NAME,),
    project_urls={
        'Code': 'https://code.stroeder.com/ldap/%s' % (PYPI_NAME,),
        'Issue tracker': 'https://code.stroeder.com/ldap/%s/issues' % (PYPI_NAME,),
    },
    keywords=['LDAP', 'DHCP', 'DNS'],
    packages=find_packages(exclude=['tests']),
    package_dir={'': '.'},
    test_suite='tests',
    python_requires='>=3.6',
    include_package_data=True,
    data_files=[],
    install_requires=[
        'setuptools',
        'ldap0>=1.4.0',
    ],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'infra-ldap-dhcphost-ptr=infraldap.dhcphostptr:sync_dhcphost_ptr',
        ],
    }
)
