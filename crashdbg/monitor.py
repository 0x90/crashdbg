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
import time

from winappdbg import System, win32, HexInput, Process, Debug

try:
    WindowsError
except NameError:
    from winappdbg.win32 import WindowsError, SLE_ERROR, SLE_MINORERROR, SLE_WARNING

# Crashdbg libs
from .handler import CrashEventHandler
from .options import Options


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

    def __init__(self, config):
        self.config = config
        self.options = Options()
        self.eventHandler = None
        self.logger = None
        self.debug = None

    def parse_config(self):
        self.options.read_config_file(self.config)
        self.parse_targets()
        self.parse_options()

        # Create the event handler
        self.eventHandler = CrashEventHandler(self.options, self.config)
        self.logger = self.eventHandler.logger

        # Create the debug object
        self.debug = Debug(self.eventHandler, bHostileCode=self.options.hostile)

    def parse_targets(self):
        """
        Parse debug targets
        """
        # Get the list of attach targets
        system = System()
        system.request_debug_privileges()
        system.scan_processes()
        attach_targets = list()
        for token in self.options.attach:
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
        self.options.attach = attach_targets

        # Get the list of console programs to execute
        console_targets = list()
        for token in self.options.console:
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
        self.options.console = console_targets

        # Get the list of windowed programs to execute
        windowed_targets = list()
        for token in self.options.windowed:
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
        self.options.windowed = windowed_targets

        # Get the list of services to attach to
        service_targets = list()
        for token in self.options.service:
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
        self.options.service = service_targets

        # If no targets were set at all, show an error message
        if not self.options.attach and not self.options.console and not self.options.windowed and not self.options.service:
            raise ValueError("no targets found!")

    def parse_options(self):
        """
            Parse options
        """
        # Warn or fail about inconsistent use of DBM databases
        if self.options.database and self.options.database.startswith('dbm://'):
            if self.options.memory and self.options.memory > 1:
                print("Warning: using options 'dbm' and 'memory' in combination can have a severe")
                print("  performance penalty.")
                print()
            if self.options.duplicates:
                if self.options.verbose:
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
        if self.options.time_limit and self.options.autodetach \
                and (self.options.windowed or self.options.console):
            count = len(self.options.windowed) + len(self.options.console)
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
        if self.options.pause and self.options.interactive:
            print("Warning: the 'pause' option is ignored when 'interactive' is set.")
            print()

    def run(self):
        """
        Run the crash logger
        """
        # Log the time we begin this run
        self.logger.log_text("Crash logger started, %s" % time.ctime())
        self.logger.log_text("Configuration: %s" % self.config)

        # Run the crash logger using this debug object
        try:
            self._start_or_attach()
            self._debugging_loop()
        except Exception:
            pass
        finally:
            # Kill all debugees on exit if requested
            if not self.options.autodetach:
                self.debug.kill_all(bIgnoreExceptions=True)

            # Log the time we finish this run
            if self.options.verbose:
                self.logger.log_text("Crash logger stopped, %s" % time.ctime())

    def _start_or_attach(self):
        """
        Start or attach to the targets
        """
        try:
            for pid in self.options.attach:
                self.debug.attach(pid)

            for cmdline in self.options.console:
                self.debug.execl(cmdline, bConsole=True, bFollow=self.options.follow)

            for cmdline in self.options.windowed:
                self.debug.execl(cmdline, bConsole=False, bFollow=self.options.follow)

            for service in self.options.service:
                status = System.get_service(service)
                if not status.ProcessId:
                    status = self._start_service(service)
                self.debug.attach(status.ProcessId)
                try:
                    self.eventHandler.pidToServices[status.ProcessId].add(service)
                except KeyError:
                    srvSet = set()
                    srvSet.add(service)
                    self.eventHandler.pidToServices[status.ProcessId] = srvSet

        # If the 'autodetach' was set to False,
        # make sure the debugees die if the debugger dies unexpectedly
        finally:
            if not self.options.autodetach:
                self.debug.system.set_kill_on_exit_mode(True)

    def _start_service(self, service, wait=True, timeout=20):
        """
        Start the service.
        """
        status = System.get_service(service)
        try:
            name = System.get_service_display_name(service)
        except WindowsError:
            name = service
        print("Starting service \"%s\"..." % name)
        # TODO: maybe add support for starting services with arguments?
        System.start_service(service)

        # Wait for it to start.
        if wait:
            status = System.get_service(service)
            while status.CurrentState == win32.SERVICE_START_PENDING:
                timeout -= 1
                if timeout <= 0:
                    self.logger.log_text("Error: timed out.")
                    msg = "Timed out waiting for service \"%s\" to start"
                    raise Exception(msg % name)
                time.sleep(0.5)
                status = System.get_service(service)

            # Done.
            self.logger.log_text("Service \"%s\" started successfully." % name)
        return status

    def _debugging_loop(self):
        """
        Main debugging loop
        """
        # If there's a time limit, calculate how much is it.
        timed_out = False
        if self.options.time_limit:
            max_time = time.time() + self.options.time_limit

        # Loop until there are no more debuggees.
        while self.debug.get_debugee_count() > 0:
            max_time = 0
            # Wait for debug events, with an optional timeout.
            while 1:
                if self.options.time_limit:
                    timed_out = time.time() > max_time
                    if timed_out:
                        break
                try:
                    self.debug.wait(100)
                    break
                except WindowsError as e:
                    if e.winerror not in (win32.ERROR_SEM_TIMEOUT,
                                          win32.WAIT_TIMEOUT):
                        self.logger.log_exc()
                        raise  # don't ignore this error
                except Exception:
                    self.logger.log_exc()
                    raise  # don't ignore this error
            if timed_out:
                self.logger.log_text("Execution time limit reached")
                break

            # Dispatch the debug event and continue execution.
            try:
                try:
                    self.debug.dispatch()
                finally:
                    self.debug.cont()
            except Exception:
                self.logger.log_exc()
                if not self.options.ignore_errors:
                    raise

            # Restart services marked for restart by the event handler.
            # Also attach to those services we want to debug.
            try:
                while self.eventHandler.srvToRestart:
                    service = self.eventHandler.srvToRestart.pop()
                    try:
                        descriptor = self._start_service(service)
                        if service in self.options.service:
                            try:
                                self.debug.attach(descriptor.ProcessId)
                                try:
                                    self.eventHandler.pidToServices[descriptor.ProcessId].add(service)
                                except KeyError:
                                    self.eventHandler.pidToServices[descriptor.ProcessId] = {service}

                            except Exception:
                                self.logger.log_exc()
                                if not self.options.ignore_errors:
                                    raise
                    except Exception:
                        self.logger.log_exc()
                        if not self.options.ignore_errors:
                            raise
            except Exception:
                self.logger.log_exc()
                if not self.options.ignore_errors:
                    raise


def run_crash_monitor(config):
    cl = CrashMonitor(config)
    cl.parse_config()
    cl.run()
