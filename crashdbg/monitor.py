#!/bin/env python
# -*- coding: utf-8 -*-

# Crash logger
# Copyright (c) 2009-2018, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import with_statement

import ntpath
import re
import time

from winappdbg import System, win32, \
    HexInput, Process, Debug

# Crashdbg libs
from .handler import CrashEventHandler
from .options import Options

try:
    WindowsError
except NameError:
    from winappdbg.win32 import WindowsError, SLE_ERROR, SLE_MINORERROR, SLE_WARNING




# XXX TODO
# Use the "signal" module to avoid having to deal with unexpected
# KeyboardInterrupt exceptions everywhere. Ideally there should be a way to
# implement some form of "critical sections" (I'm using the term loosely here,
# meaning "sections that can't be interrupted by the user"), something like
# this: a global flag to enable and disable raising KeyboardInterrupt, and a
# couple functions to set it. The function that enables back KeyboardInterrupt
# should check for a queued interruption request. Some experimenting is needed
# to see how well this would behave on a Windows environment.

# ==============================================================================

# XXX TODO
# * Capture stderr from the debugees?
# * Unless the full memory snapshot was requested, the debugger could return
#   DEBUG_CONTINUE and store the crash info in the database in background,
#   while the debugee tries to handle the exception.


class CrashMonitor(object):

    def read_config_file(self, config):
        """
        Read the configuration file
        """
        # Initial options object with default values
        options = Options()

        # Keep track of duplicated options
        opt_history = set()

        # Regular expression to split the command and the arguments
        regexp = re.compile(r'(\S+)\s+(.*)')

        # Open the config file
        with open(config, 'rU') as fd:
            number = 0
            while 1:

                # Read a line
                line = fd.readline()
                if not line:
                    break
                number += 1

                # Strip the extra whitespace
                line = line.strip()

                # If it's a comment line or a blank line, discard it
                if not line or line.startswith('#'):
                    continue

                # Split the option and its arguments
                match = regexp.match(line)
                if not match:
                    msg = "cannot parse line %d of config file %s"
                    msg = msg % (number, config)
                    raise RuntimeError(msg)
                key, value = match.groups()

                # Targets
                if key == 'attach':
                    if value:
                        options.attach.append(value)
                elif key == 'console':
                    if value:
                        options.console.append(value)
                elif key == 'windowed':
                    if value:
                        options.windowed.append(value)
                elif key == 'service':
                    if value:
                        options.service.append(value)

                # List options
                elif key == 'break_at':
                    options.break_at.extend(self._parse_list(value))
                elif key == 'stalk_at':
                    options.stalk_at.extend(self._parse_list(value))
                elif key == 'action':
                    options.action.append(value)

                # Switch options
                else:

                    # Warn about duplicated options
                    if key in opt_history:
                        print("Warning: duplicated option %s in line %d"
                              " of config file %s" % (key, number, config))
                        print()
                    else:
                        opt_history.add(key)

                    # Output options
                    if key == 'verbose':
                        options.verbose = self._parse_boolean(value)
                    elif key == 'logfile':
                        options.logfile = value
                    elif key == 'database':
                        options.database = value
                    elif key == 'duplicates':
                        options.duplicates = self._parse_boolean(value)
                    elif key == 'firstchance':
                        options.firstchance = self._parse_boolean(value)
                    elif key == 'memory':
                        options.memory = int(value)
                    elif key == 'ignore_python_errors':
                        options.ignore_errors = self._parse_boolean(value)

                    # Debugging options
                    elif key == 'hostile':
                        options.hostile = self._parse_boolean(value)
                    elif key == 'follow':
                        options.follow = self._parse_boolean(value)
                    elif key == 'autodetach':
                        options.autodetach = self._parse_boolean(value)
                    elif key == 'restart':
                        options.restart = self._parse_boolean(value)

                    # Tracing options
                    elif key == 'pause':
                        options.pause = self._parse_boolean(value)
                    elif key == 'interactive':
                        options.interactive = self._parse_boolean(value)
                    elif key == 'time_limit':
                        options.time_limit = int(value)
                    elif key == 'echo':
                        options.echo = self._parse_boolean(value)
                    elif key == 'action_events':
                        options.action_events = self._parse_list(value)
                    elif key == 'crash_events':
                        options.crash_events = self._parse_list(value)

                    # Unknown option
                    else:
                        msg = ("unknown option %s in line %d"
                               " of config file %s") % (key, number, config)
                        raise RuntimeError(msg)

        # Return the options object
        return options

    def parse_targets(self, options):
        # Get the list of attach targets
        system = System()
        system.request_debug_privileges()
        system.scan_processes()
        attach_targets = list()
        for token in options.attach:
            if not token:
                continue


            try:
                dwProcessId = HexInput.integer(str(token))
            except ValueError:
                dwProcessId = None
            if dwProcessId is not None:
                if not system.has_process(dwProcessId):
                    raise ValueError("can't find process %d" % dwProcessId)
                try:
                    process = Process(dwProcessId)
                    process.open_handle()
                    process.close_handle()
                except WindowsError as e:
                    raise ValueError("can't open process %d: %s" % (dwProcessId, e))
                attach_targets.append(dwProcessId)
            else:
                matched = system.find_processes_by_filename(str(token))
                if not matched:
                    raise ValueError("can't find process %s" % token)
                for process, name in matched:
                    dwProcessId = process.get_pid()
                    try:
                        process = Process(dwProcessId)
                        process.open_handle()
                        process.close_handle()
                    except WindowsError as e:
                        raise ValueError("can't open process %d: %s" % (dwProcessId, e))
                    attach_targets.append(dwProcessId)
        options.attach = attach_targets

        # Get the list of console programs to execute
        console_targets = list()
        for token in options.console:
            if not token:
                continue
            vector = System.cmdline_to_argv(token)
            filename = vector[0]
            if not ntpath.exists(filename):
                try:
                    filename = win32.SearchPath(None, filename, '.exe')[0]
                except WindowsError as e:
                    raise ValueError("error searching for %s: %s" % (filename, str(e)))
                vector[0] = filename
            token = System.argv_to_cmdline(vector)
            console_targets.append(token)
        options.console = console_targets

        # Get the list of windowed programs to execute
        windowed_targets = list()
        for token in options.windowed:
            if not token:
                continue
            vector = System.cmdline_to_argv(token)
            filename = vector[0]
            if not ntpath.exists(filename):
                try:
                    filename = win32.SearchPath(None, filename, '.exe')[0]
                except WindowsError as e:
                    raise ValueError("error searching for %s: %s" % (filename, str(e)))
                vector[0] = filename
            token = System.argv_to_cmdline(vector)
            windowed_targets.append(token)
        options.windowed = windowed_targets

        # Get the list of services to attach to
        service_targets = list()
        for token in options.service:
            if not token:
                continue
            try:
                status = System.get_service(token)
            except WindowsError:
                try:
                    token = System.get_service_from_display_name(token)
                    status = System.get_service(token)
                except WindowsError as e:
                    raise ValueError("error searching for service %s: %s" % (token, str(e)))
            if not hasattr(status, 'ProcessId'):
                raise ValueError("service targets not supported by the current platform")
            service_targets.append(token.lower())
        options.service = service_targets

        # If no targets were set at all, show an error message
        if not options.attach and not options.console and not options.windowed and not options.service:
            raise ValueError("no targets found!")

    def parse_options(self, options):
        # Warn or fail about inconsistent use of DBM databases
        if options.database and options.database.startswith('dbm://'):
            if options.memory and options.memory > 1:
                print("Warning: using options 'dbm' and 'memory' in combination can have a severe")
                print("  performance penalty.")
                print()
            if options.duplicates:
                if options.verbose:
                    print("Warning: inconsistent use of 'duplicates'")
                    print("  DBM databases do not allow duplicate entries with the same key.")
                    print("  This means that when the same crash is found more than once it will be logged")
                    print("  to standard output each time, but will only be saved once into the database.")
                    print()
                else:
                    msg = "inconsistent use of 'duplicates': "
                    msg += "DBM databases do not allow duplicate entries with the same key"
                    raise ValueError(msg)

        # Warn about inconsistent use of time_limit
        if options.time_limit and options.autodetach \
                and (options.windowed or options.console):
            count = len(options.windowed) + len(options.console)
            print()
            print("Warning: inconsistent use of 'time_limit'")
            if count == 1:
                print("  An execution time limit was set, but the launched process won't be killed.")
            else:
                print("  An execution time limit was set, but %d launched processes won't be killed." % count)
            print("  Set 'autodetach' to false to make sure debugees are killed on exit.")
            print("  Alternatively use 'attach' instead of launching new processes.")
            print()
        # Warn about inconsistent use of pause and interactive
        if options.pause and options.interactive:
            print("Warning: the 'pause' option is ignored when 'interactive' is set.")
            print()

    def _parse_list(self, value):
        tokens = set([token.strip() for token in value.lower().split(',')])
        return tokens

    def _parse_boolean(self, value):
        value = value.strip().lower()
        if value == 'true' or value == 'yes' or value == 'y':
            return True
        if value == 'false' or value == 'no' or value == 'n':
            return False
        return bool(int(value))

    def run(self, config, options):
        """
        Run the crash logger
        """

        # Create the event handler
        eventHandler = CrashEventHandler(options, config)
        logger = eventHandler.logger

        # Log the time we begin this run
        if options.verbose:
            logger.log_text("Crash logger started, %s" % time.ctime())
            logger.log_text("Configuration: %s" % config)

        # Run
        try:
            # Create the debug object
            with Debug(eventHandler, bHostileCode=options.hostile) as debug:

                # Run the crash logger using this debug object
                try:
                    self._start_or_attach(debug, options, eventHandler)
                    try:
                        self._debugging_loop(debug, options, eventHandler)
                    except Exception:
                        if not options.verbose:
                            raise
                        return

                # Kill all debugees on exit if requested
                finally:
                    if not options.autodetach:
                        debug.kill_all(bIgnoreExceptions=True)

        # Log the time we finish this run
        finally:
            if options.verbose:
                logger.log_text("Crash logger stopped, %s" % time.ctime())

    def _start_or_attach(self, debug, options, eventHandler):
        logger = eventHandler.logger

        # Start or attach to the targets
        try:
            for pid in options.attach:
                debug.attach(pid)
            for cmdline in options.console:
                debug.execl(cmdline, bConsole=True,
                            bFollow=options.follow)
            for cmdline in options.windowed:
                debug.execl(cmdline, bConsole=False,
                            bFollow=options.follow)
            for service in options.service:
                status = System.get_service(service)
                if not status.ProcessId:
                    status = self._start_service(service, logger)
                debug.attach(status.ProcessId)
                try:
                    eventHandler.pidToServices[status.ProcessId].add(service)
                except KeyError:
                    srvSet = set()
                    srvSet.add(service)
                    eventHandler.pidToServices[status.ProcessId] = srvSet

        # If the 'autodetach' was set to False,
        # make sure the debugees die if the debugger dies unexpectedly
        finally:
            if not options.autodetach:
                debug.system.set_kill_on_exit_mode(True)

    @staticmethod
    def _start_service(service, logger):

        # Start the service.
        status = System.get_service(service)
        try:
            name = System.get_service_display_name(service)
        except WindowsError:
            name = service
        print("Starting service \"%s\"..." % name)
        # TODO: maybe add support for starting services with arguments?
        System.start_service(service)

        # Wait for it to start.
        timeout = 20
        status = System.get_service(service)
        while status.CurrentState == win32.SERVICE_START_PENDING:
            timeout -= 1
            if timeout <= 0:
                logger.log_text("Error: timed out.")
                msg = "Timed out waiting for service \"%s\" to start"
                raise Exception(msg % name)
            time.sleep(0.5)
            status = System.get_service(service)

        # Done.
        logger.log_text("Service \"%s\" started successfully." % name)
        return status

    # Main debugging loop
    def _debugging_loop(self, debug, options, eventHandler):

        # Get the logger.
        logger = eventHandler.logger

        # If there's a time limit, calculate how much is it.
        timedOut = False
        if options.time_limit:
            maxTime = time.time() + options.time_limit

        # Loop until there are no more debuggees.
        while debug.get_debugee_count() > 0:
            maxTime = 0
            # Wait for debug events, with an optional timeout.
            while 1:
                if options.time_limit:
                    timedOut = time.time() > maxTime
                    if timedOut:
                        break
                try:
                    debug.wait(100)
                    break
                except WindowsError as e:
                    if e.winerror not in (win32.ERROR_SEM_TIMEOUT,
                                          win32.WAIT_TIMEOUT):
                        logger.log_exc()
                        raise  # don't ignore this error
                except Exception:
                    logger.log_exc()
                    raise  # don't ignore this error
            if timedOut:
                logger.log_text("Execution time limit reached")
                break

            # Dispatch the debug event and continue execution.
            try:
                try:
                    debug.dispatch()
                finally:
                    debug.cont()
            except Exception:
                logger.log_exc()
                if not options.ignore_errors:
                    raise

            # Restart services marked for restart by the event handler.
            # Also attach to those services we want to debug.
            try:
                while eventHandler.srvToRestart:
                    service = eventHandler.srvToRestart.pop()
                    try:
                        descriptor = self._start_service(service, logger)
                        if service in options.service:
                            try:
                                debug.attach(descriptor.ProcessId)
                                try:
                                    eventHandler.pidToServices[descriptor.ProcessId].add(service)
                                except KeyError:
                                    srvSet = set()
                                    srvSet.add(service)
                                    eventHandler.pidToServices[descriptor.ProcessId] = srvSet
                            except Exception:
                                logger.log_exc()
                                if not options.ignore_errors:
                                    raise
                    except Exception:
                        logger.log_exc()
                        if not options.ignore_errors:
                            raise
            except Exception:
                logger.log_exc()
                if not options.ignore_errors:
                    raise
