# CrashDBG

Application crash logger + report generator. 

Based on WinAppDbg crash logger by Mario Vilas (mvilas at gmail.com)

## Setup

To setup

```
pip install .
```

## EXE

Create .spec file fot single exe output
```
pyinstaller -F -c --uac-admin crashdbg/cli.py
```

Build single exe
```
pyinstaller crashdbg.spec
```
