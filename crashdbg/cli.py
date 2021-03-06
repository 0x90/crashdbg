import os
import sys

import better_exceptions
import click
from winappdbg import System

from crashdbg import run_crash_monitor, print_report_for_database, open_database, Options

better_exceptions.patch_logging()


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
def cli():
    """
    CrashDBG - Application crash monitor and report generator

    Mario Vilas  (mvilas@gmail.com)
    0x90 (root@0x90.ru)
    """
    pass


@cli.command()
def info():
    """
    Show system information
    """
    click.secho()
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        print('running in a PyInstaller bundle')
    else:
        print('running in a normal Python process')
    print("Postmorten debugger: %s" % System.get_postmortem_debugger())


@cli.command()
def symfix():
    """
    Fix debug symbols PATH
    """
    System.fix_symbol_store_path()


@cli.command()
def configure():
    """
    Configure CrashDBG with the help of wizard.
    """
    pass


@cli.command()
@click.argument('config')
def install(config):
    """
    Install as postmorten debugger
    """
    # Not yet compatible with Cygwin.
    if sys.platform == "cygwin":
        raise NotImplementedError("This feature is not available on Cygwin")

    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        print('running in a PyInstaller bundle')
    else:
        print('running in a normal Python process')

    # Calculate the command line to run in JIT mode
    # TODO maybe fix this so it works with py2exe?
    interpreter = os.path.abspath(sys.executable)
    script = os.path.abspath(__file__)
    config = os.path.abspath(config)
    argv = [interpreter, script, '--jit', config, '%ld']
    cmdline = System.argv_to_cmdline(argv)
    previous = System.get_postmortem_debugger()
    print("Previous postmorten debugger was: %s" % previous)
    System.set_postmortem_debugger(cmdline)


@cli.command()
def uninstall():
    """
    Uninstall crash monitor as postmorten debugger
    """
    System.set_postmortem_debugger()


@cli.command()
@click.argument('config', nargs=-1, type=click.Path(exists=True))
def run(config):
    """
    Run application crash monitor
    """
    for config_path in config:
        run_crash_monitor(config_path)


@cli.command()
@click.option("-v", "--verbose", help="produces a full report")
# @click.option("-q", "--quiet", help="produces a brief report")
@click.argument('config', nargs=-1, type=click.Path(exists=True))
def report(verbose, config):
    """
    Generate crash report from crash DB
    """
    options = Options()
    options.verbose = verbose
    for filename in config:
        cc = open_database(filename)
        print_report_for_database(cc, options)


if __name__ == '__main__':
    cli()
