# CrashDBG

Application crash logger + report generator. 

Based on WinAppDbg crash logger by Mario Vilas (mvilas at gmail.com)

## Setup

pip install .

Create single exe

pyinstaller -F -c --uac-admin crashdbg/cli.py 

pyinstaller crashdbg.spec