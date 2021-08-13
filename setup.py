#!/bin/env python
# -*- coding: utf-8 -*-
# from pylint.__pkginfo__ import extras_require
from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext


class BuildExtCommand(build_ext):

    def build_exe(self):
        import PyInstaller.__main__
        PyInstaller.__main__.run([
            'my_script.py',
            '--onefile',
            '--windowed'
        ])

    def run(self):
        self.build_exe()
        build_ext.run(self)
        # subprocess.check_output('python PythonService.py --startup auto install'.split())


setup(
    name='crashdbg',
    version='0.3.0',
    packages=find_packages(),
    install_requires=['Click',
                      'coloredlogs',
                      'better_exceptions',
                      # 'pywin32',
                      # 'pywintypes',
                      'watchdog',
                      'winappdbg @ git+https://github.com/MarioVilas/winappdbg#egg=winappdbg',
                      ],
    extras_require={
        "PyInstaller": ["PyInstaller"],
    },
    include_package_data=True,
    package_data={
        "crashdbg": ["crashdbg/configs/*.cfg"]
    },

    # Although 'package_data' is the preferred approach, in some case you may
    # need to place data files outside of your packages.
    # see http://docs.python.org/3.4/distutils/setupscript.html#installing-additional-files
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    data_files=[],
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
    python_requires='=2.7',
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    cmdclass={
        'build_ext': BuildExtCommand,
    },
)
