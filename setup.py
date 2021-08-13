from setuptools import setup, find_packages

setup(
    name='crashdbg',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Click',
        'winappdbg @ git+https://github.com/MarioVilas/winappdbg#egg=winappdbg',
    ],
    entry_points={
        'console_scripts': [
            'crashdbg = crashdbg.cli:cli',
        ],
    },
    url='https://github.com/0x90/crashdbg',
    license='BSD',
    author='0x90',
    author_email='oleg.kupreev@gmail.com',
    description='Application crash logger and report generator.'
)