#!/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext


class BuildExtCommand(build_ext):

    def build_exe(self):
        import PyInstaller.__main__
        PyInstaller.__main__.run([
            'crashdbg/cli.py',
            '--onefile',
            '--console',
            '--name',
            'crashdbg'
        ])

    def run(self):
        self.build_exe()
        build_ext.run(self)


setup(
    name='crashdbg',
    version='0.3.1',
    packages=find_packages(),
    install_requires=['Click',
                      'coloredlogs',
                      'better_exceptions',
                      # 'watchdog',
                      'winappdbg @ git+https://github.com/MarioVilas/winappdbg#egg=winappdbg',
                      ],
    extras_require={
        "PyInstaller": ["PyInstaller"
                        'pywin32',
                        'pywintypes',
                        ],
    },
    include_package_data=True,
    package_data={
        "configs": ["*.cfg"]
    },
    # Although 'package_data' is the preferred approach, in some case you may
    # need to place data files outside of your packages.
    # see http://docs.python.org/3.4/distutils/setupscript.html#installing-additional-files
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    # data_files=[],
    entry_points={
        'console_scripts': [
            'crashdbg = crashdbg.cli:cli',
        ],
    },
    url='https://github.com/0x90/crashdbg',
    license='BSD',
    author='0x90',
    author_email='oleg.kupreev@gmail.com',
    description='Application crash logger and report generator.',
    long_description='Application crash logger and report generator.',
    long_description_content_type="text/markdown",
    python_requires='==2.7',
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    cmdclass={
        'build_ext': BuildExtCommand,
    },
)
