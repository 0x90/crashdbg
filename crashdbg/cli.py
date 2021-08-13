import os
import sys

import click
from winappdbg import System
from crashdbg.monitor import CrashMonitor


@click.group()
def cli():
    """
    CrashDBG - Application crash monitor and report generator
    """
    print("Crash logger report")
    print("by Mario Vilas (mvilas at gmail.com)")


@cli.command()
def info():
    """
    Show system information
    """
    dbg = System.get_postmortem_debugger()
    print("Postmorten debugger: %s" % dbg)


@cli.command()
@click.argument('config')
def install(config):
    """
    Install as postmorten debugger
    """
    # Not yet compatible with Cygwin.
    if sys.platform == "cygwin":
        raise NotImplementedError(
            "This feature is not available on Cygwin")

    # Calculate the command line to run in JIT mode
    # TODO maybe fix this so it works with py2exe?
    interpreter = os.path.abspath(sys.executable)
    script = os.path.abspath(__file__)
    config = os.path.abspath(config)
    argv = [interpreter, script, '--jit', config, '%ld']
    cmdline = System.argv_to_cmdline(argv)
    previous = System.get_postmortem_debugger()
    print("Previous JIT debugger was: %s" % previous)
    System.set_postmortem_debugger(cmdline)


@cli.command()
def uninstall():
    """
    Run Application crash monitor
    """
    System.set_postmortem_debugger()


@cli.command()
@click.argument('config')
def run(config):
    """
    Run Application crash monitor
    """
    cl = CrashMonitor()
    options = cl.read_config_file(config)
    cl.parse_targets(options)
    cl.parse_options(options)
    cl.run(config, options)


@cli.command()
@click.option("-v", "--verbose", help="produces a full report")
@click.option("-q", "--quiet", help="produces a brief report")
@click.argument('config')
def report(verbose, quiet):
    """
    Generate crash report from crash DB
    """
    parameters = filter_duplicates(parameters)
    parameters = filter_inexistent_files(parameters)
    for filename in parameters:
        cc = open_database(filename)
        print_report_for_database(cc, options)

