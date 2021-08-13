#!/bin/env python
# -*- coding: utf-8 -*-

# Crash logger report (see crash_logger.py)
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

import os
import time

from winappdbg import CrashContainer, CrashDictionary
from .monitor import CrashMonitor


def filter_duplicates(old_list):
    new_list = list()
    for filename in old_list:
        if filename not in new_list:
            new_list.append(filename)
        else:
            print("Skipping duplicate file: %s" % filename)
    return new_list


def filter_inexistent_files(old_list):
    new_list = list()
    for filename in old_list:
        if os.path.exists(filename):
            new_list.append(filename)
        else:
            print("Cannot find file: %s" % filename)
    return new_list


def open_database(filename):
    """
    Parse the configuration file to get the database URI.
    """
    print("Opening configuration file: %s" % filename)
    cl = CrashMonitor()
    options = cl.read_config_file(filename)

    # Open the database.
    try:
        if not options.database:
            print("Warning: no database configured here, ignored")
            return
        elif options.database.startswith('dbm://'):
            dbfile = options.database[6:]
            print("Connecting to DBM database file: %s" % dbfile)
            cc = CrashContainer(dbfile)
        else:
            print("Connecting to database: %s" % options.database)
            cc = CrashDictionary(options.database)
    except Exception as e:
        print("Error connecting to the database: %s" % e)
        return

    # Return the crash container.
    return cc


def print_report_for_database(cc, options):
    if cc is not None:
        count = cc.__len__()
        if not count:
            print("No crashes to report.")
        else:
            print("Found %d crashes:" % count)
            print('-' * 79)
            print_crash_report(cc, options)


def print_crash_report(cc, options):
    ccl = [(c.timeStamp, c) for c in cc]  # XXX may use a lot of memory
    ccl.sort()  # XXX may be inaccurate if timestamps are repeated
    for (timeStamp, c) in ccl:
        local = time.localtime(timeStamp)
        ldate = time.strftime("%x", local)
        ltime = time.strftime("%X", local)
        msecs = (c.timeStamp % 1) * 1000
        msg = '%s %s.%04d' % (ldate, ltime, msecs)
        print(msg)
        if options.verbose:
            report = c.fullReport()
        else:
            report = c.briefReport() + '\n'
        if isinstance(report, unicode):
            report = report.encode('UTF8')  # XXX HORRIBLE HACK!
        print(report)
        print('-' * 79)


