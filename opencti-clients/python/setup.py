#!/usr/bin/python3
# coding: utf-8

from setuptools import setup

try:
    from pypandoc import convert
    read_md = lambda f: convert(f, 'rst')
except ImportError:
    print("warning: pypandoc module not found, could not convert Markdown to RST")
    read_md = lambda f: open(f, 'r').read()

setup(
    name='pycti',
    version='1.0.0',
    description='Python API client for OpenCTI.',
    long_description=read_md('README.md'),
    author='Luatix',
    author_email='contact@luatix.org',
    maintainer='Luatix',
    url='https://github.com/LuatixHQ/OpenCTI/opencti-clients/python',
    license='AGPL-V3',
    packages=['pycti'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Natural Language :: English',
        'Natural Language :: French',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    include_package_data=True,
    install_requires=['requests']
)