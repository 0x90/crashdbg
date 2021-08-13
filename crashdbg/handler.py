from winappdbg import EventHandler, Crash, Logger, DummyCrashContainer, \
    CrashDictionary, CrashContainer, win32, System, \
    HexDump, Module
from winappdbg.win32 import SLE_ERROR, SLE_MINORERROR, SLE_WARNING

__all__ = [
    'CrashEventHandler',
]


class CrashEventHandler(EventHandler):
    """
    Event handler that logs all events to standard output.
    It also remembers crashes, bugs or otherwise interesting events.

    @type crashCollector: class
    @cvar crashCollector:
        Crash collector class. Typically L{Crash} or a custom subclass of it.

        Most users don't ever need to change this.
        See: U{http://winappdbg.readthedocs.io/en/latest/Signature.html}
    """

    # Default crash collector is our good old Crash class.
    crashCollector = Crash

    def __init__(self, options, currentConfig=None):
        # Copy the user-defined options.
        self.options = options
        # Copy the configuration used in this fuzzing session.
        self.currentConfig = currentConfig
        # Create the logger object.
        self.logger = Logger(options.logfile, options.verbose)

        # Create the crash container.
        self.knownCrashes = self._new_crash_container()

        # Create the cache of resolved labels.
        self.labelsCache = dict()  # pid -> label -> address

        # Create the map of target services and their process IDs.
        self.pidToServices = dict()  # pid -> set(service...)

        # Create the set of services marked for restart.
        self.srvToRestart = set()

        # Call the base class constructor.
        super(CrashEventHandler, self).__init__()

    def _new_crash_container(self):
        url = self.options.database
        if not url:
            return DummyCrashContainer(
                allowRepeatedKeys=self.options.duplicates)
        if url.startswith('dbm://'):
            url = url[6:]
            return CrashContainer(url,
                                  allowRepeatedKeys=self.options.duplicates)
        return CrashDictionary(url,
                               allowRepeatedKeys=self.options.duplicates)

    def _add_crash(self, event, bFullReport=None, bLogEvent=True):
        """
        Add the crash to the database.
        """
        # Unless forced either way, full reports are generated for exceptions.
        if bFullReport is None:
            bFullReport = event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT

        # Generate a crash object.
        crash = self.crashCollector(event)
        crash.addNote('Config: %s' % self.currentConfig)

        # Determine if the crash was previously known.
        # If we're allowing duplicates, treat all crashes as new.
        bNew = self.options.duplicates or crash not in self.knownCrashes

        # Add the crash object to the container.
        if bNew:
            crash.fetch_extra_data(event, self.options.memory)
            self.knownCrashes.add(crash)

        # Log the crash event.
        if bLogEvent and self.logger.is_enabled():
            if bFullReport and bNew:
                msg = crash.fullReport(bShowNotes=False)
            else:
                msg = crash.briefReport()
            self.logger.log_event(event, msg)

        # The first element of the tuple is the Crash object.
        # The second element is True if the crash is new, False otherwise.
        return crash, bNew

    def _is_action_event(self, event):
        """
        Determine if this is an event we must take action on.
        """
        return self.options.action and self._is_event_in_list(event, self.options.action_events)

    def _is_crash_event(self, event):
        """
        Determine if this is a crash event.
        """
        return self._is_event_in_list(event, self.options.crash_events)

    def _is_event_in_list(self, event, event_list):
        """
        Common implementation of _is_action_event() and _is_crash_event().
        """
        return \
            ('event' in event_list) or ('exception' in event_list and
                                        (event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and
                                         (event.is_last_chance() or self.options.firstchance))) or \
            (event.eventMethod in event_list)

    def _action(self, event, crash=None):
        """
        Actions to take for events.
        """
        # Pause if requested.
        if self.options.pause:
            input("Press enter to continue...")

        try:
            # Run the configured commands after finding a crash if requested.
            self._run_action_commands(event, crash)
        finally:
            # Enter interactive mode if requested.
            if self.options.interactive:
                event.debug.interactive(bConfirmQuit=False)

    def _default_event_processing(self, event, full_report=None, log_event=False):
        """
        Most events are processed here. Others have specific quirks on when to consider them actionable or crashes.
        """
        crash = None
        new_crash = True
        try:
            if self._is_crash_event(event):
                crash, new_crash = self._add_crash(event, full_report, log_event)
        finally:
            if new_crash and self._is_action_event(event):
                self._action(event, crash)

    def _run_action_commands(self, event, crash=None):
        # Run the configured commands after finding a crash.
        # Wait until each command completes before executing the next.
        # To avoid waiting, use the "start" command.
        for action in self.options.action:
            if '%' in action:
                if not crash:
                    crash = self.crashCollector(event)
                action = self._replace_action_variables(action, crash)
            action = "cmd.exe /c " + action
            system = System()
            process = system.start_process(action, bConsole=True)
            process.wait()

    def _replace_action_variables(self, action, crash):
        """
        Make the variable replacements in an action command line string.
        """
        # %COUNT% - Number of crashes currently stored in the database
        if '%COUNT%' in action:
            action = action.replace('%COUNT%', str(len(self.knownCrashes)))

        # %EXCEPTIONCODE% - Exception code in hexa
        if '%EXCEPTIONCODE%' in action:
            exceptionCode = HexDump.address(crash.exceptionCode) if crash.exceptionCode else HexDump.address(0)
            action = action.replace('%EXCEPTIONCODE%', exceptionCode)

        # %EVENTCODE% - Event code in hexa
        if '%EVENTCODE%' in action:
            action = action.replace('%EVENTCODE%', HexDump.address(crash.eventCode))

        # %EXCEPTION% - Exception name, human readable
        if '%EXCEPTION%' in action:
            exceptionName = crash.exceptionName if crash.exceptionName else 'Not an exception'
            action = action.replace('%EXCEPTION%', exceptionName)

        # %EVENT% - Event name, human readable
        if '%EVENT%' in action:
            action = action.replace('%EVENT%', crash.eventName)

        # %PC% - Contents of EIP, in hexa
        if '%PC%' in action:
            action = action.replace('%PC%', HexDump.address(crash.pc))

        # %SP% - Contents of ESP, in hexa
        if '%SP%' in action:
            action = action.replace('%SP%', HexDump.address(crash.sp))

        # %FP% - Contents of EBP, in hexa
        if '%FP%' in action:
            action = action.replace('%FP%', HexDump.address(crash.fp))

        # %WHERE% - Location of the event (a label or address)
        if '%WHERE%' in action:
            if crash.labelPC:
                try:
                    labelPC = str(crash.labelPC)
                except UnicodeError:
                    labelPC = HexDump.address(crash.pc)
            else:
                labelPC = HexDump.address(crash.pc)
            action = action.replace('%WHERE%', labelPC)

        return action

    def _get_location(self, event, address):
        """
        Get the location of the code that triggered the event.
        """
        label = event.get_process().get_label_at_address(address)
        return label if label else HexDump.address(address)

    def _log_exception(self, event):
        """
        Log an exception as a single line of text.
        """
        what = event.get_exception_description()
        address = event.get_exception_address()
        where = self._get_location(event, address)
        chance = 'first' if event.is_first_chance() else 'second'
        msg = "%s (%s chance) at %s" % (what, chance, where)
        self.logger.log_event(event, msg)

    def _set_breakpoints(self, event):
        """
        Set all breakpoints that can be set at each create process or load dll event.
        """
        method = event.debug.break_at
        bplist = self.options.break_at
        self._set_breakpoints_from_list(event, bplist, method)
        method = event.debug.stalk_at
        bplist = self.options.stalk_at
        self._set_breakpoints_from_list(event, bplist, method)

    def _set_breakpoints_from_list(self, event, bplist, method):
        """
        Set a list of breakppoints using the given method.
        """
        dwProcessId = event.get_pid()
        aModule = event.get_module()
        for label in bplist:
            if dwProcessId not in self.labelsCache:
                self.labelsCache[dwProcessId] = dict()
            # XXX FIXME
            # We may have a problem here for some ambiguous labels...
            if label not in self.labelsCache[dwProcessId]:
                try:
                    address = aModule.resolve_label(label)
                except ValueError:
                    address = None
                except RuntimeError:
                    address = None
                except WindowsError:
                    address = None
                if address is not None:
                    self.labelsCache[dwProcessId][label] = address
                    try:
                        method(dwProcessId, address)
                    except RuntimeError:
                        pass
                    except WindowsError:
                        pass

    def event(self, event):
        """
        Handle all events not handled by the following methods.
        """
        self._default_event_processing(event, log_event=True)

    def create_process(self, event):
        """
        Handle the create process events.
        """
        try:
            try:

                # Log the event.
                if self.logger.is_enabled():
                    start_address = event.get_start_address()
                    filename = event.get_filename()
                    if not filename:
                        filename = Module.unknown
                    if start_address:
                        where = HexDump.address(start_address)
                        msg = "Process %s started, entry point at %s"
                        msg = msg % (filename, where)
                    else:
                        msg = "Attached to process %s" % filename
                    self.logger.log_event(event, msg)

            finally:
                # Process the event.
                self._default_event_processing(event)

        finally:
            # Set user-defined breakpoints for this process.
            self._set_breakpoints(event)

    def create_thread(self, event):
        """
        Handle the create thread events.
        """
        try:

            # Log the event.
            if self.logger.is_enabled():
                lpStartAddress = event.get_start_address()
                msg = "Thread started, entry point at %s" % self._get_location(event,
                                                                               lpStartAddress) if lpStartAddress else "Attached to thread"
                self.logger.log_event(event, msg)

        finally:

            # Process the event.
            self._default_event_processing(event)

    def load_dll(self, event):
        """
        Handle the load dll events.
        """
        try:
            # Log the event.
            if self.logger.is_enabled():
                aModule = event.get_module()
                lpBaseOfDll = aModule.get_base()
                fileName = aModule.get_filename()
                if not fileName:
                    fileName = "a new module"
                msg = "Loaded %s at %s"
                msg = msg % (fileName, HexDump.address(lpBaseOfDll))
                self.logger.log_event(event, msg)

        finally:
            # Process the event.
            self._default_event_processing(event)
            # Set user-defined breakpoints for this module.
            self._set_breakpoints(event)

    def exit_process(self, event):
        """
        Handle the exit process events.
        """
        try:

            # Log the event.
            msg = "Process terminated, exit code %x" % event.get_exit_code()
            self.logger.log_event(event, msg)

        finally:
            try:

                # Process the event.
                self._default_event_processing(event)

            finally:
                try:

                    # Clear the labels cache for this process.
                    dwProcessId = event.get_pid()
                    if dwProcessId in self.labelsCache:
                        del self.labelsCache[dwProcessId]

                finally:
                    # Restart if requested.
                    if self.options.restart:
                        dwProcessId = event.get_pid()
                        aProcess = event.get_process()

                        # Find out which services were running here.
                        # FIXME: make this more efficient!
                        currentServices = set([d.ServiceName.lower() for d in aProcess.get_services()])
                        debuggedServices = set(self.options.service)
                        debuggedServices.intersection_update(currentServices)

                        # We have services dying here, mark them for restart.
                        # They are restarted later at the debug loop.
                        if debuggedServices:
                            self.srvToRestart.update(currentServices)

                        # Now check if this process had hosted any of our
                        # target services before. If the service is stopped
                        # externally we won't know it here, so we need to
                        # keep this information beforehand.
                        targetServices = self.pidToServices.pop(dwProcessId, set())
                        if targetServices:
                            self.srvToRestart.update(targetServices)

                        # No services here, restart the process directly.
                        if not debuggedServices and not targetServices:
                            cmdline = aProcess.get_command_line()
                            event.debug.execl(cmdline)

    def exit_thread(self, event):
        """
        Handle the exit thread events.
        """
        try:
            # Log the event.
            msg = "Thread terminated, exit code %x" % event.get_exit_code()
            self.logger.log_event(event, msg)

        finally:
            # Process the event.
            self._default_event_processing(event, log_event=False)

    def unload_dll(self, event):
        """
        Handle the unload dll events.
        """
        # XXX FIXME
        # We should be updating the labels cache here,
        # otherwise we might lose the breakpoints if
        # the dll gets unloaded and then loaded again.

        try:
            # Log the event.
            if self.logger.is_enabled():
                aModule = event.get_module()
                lpBaseOfDll = aModule.get_base()
                fileName = aModule.get_filename()
                if not fileName:
                    fileName = 'a module'

                msg = "Unloaded %s at %s" % (fileName, HexDump.address(lpBaseOfDll))
                self.logger.log_event(event, msg)

        finally:
            # Process the event.
            self._default_event_processing(event)

    def output_string(self, event):
        """
        Handle the debug output string events.
        """
        try:
            # Echo the debug strings.
            if self.options.echo:
                win32.OutputDebugString(event.get_debug_string())
        finally:
            # Process the event.
            self._default_event_processing(event, log_event=True)

    def rip(self, event):
        """
        Handle the RIP events.
        """
        try:
            # Log the event.
            if self.logger.is_enabled():
                errorCode = event.get_rip_error()
                errorType = event.get_rip_type()
                if errorType == 0:
                    msg = "RIP error at thread %d, code %x"
                elif errorType == SLE_ERROR:
                    msg = "RIP fatal error at thread %d, code %x"
                elif errorType == SLE_MINORERROR:
                    msg = "RIP minor error at thread %d, code %x"
                elif errorType == SLE_WARNING:
                    msg = "RIP warning at thread %d, code %x"
                else:
                    msg = "RIP error type %d, code %%x" % errorType
                self.logger.log_event(event, msg % errorCode)

        finally:
            # Process the event.
            self._default_event_processing(event)

    def _post_exception(self, event):
        # Kill the process if it's a second chance exception.
        # Otherwise we'd get stuck in an infinite loop.
        if hasattr(event, 'is_last_chance') and event.is_last_chance():
            ##            try:
            ##                event.get_thread().set_pc(
            ##                  event.get_process().resolve_symbol('kernel32!ExitProcess')
            ##                )
            ##            except Exception:
            event.get_process().kill()

    def exception(self, event):
        """
        Handle all exceptions not handled by the following methods.
        """
        try:

            # This is almost identical to the default processing.
            # The difference is how logging is handled.
            crash = None
            bNew = True
            try:
                if self._is_crash_event(event):
                    crash, bNew = self._add_crash(event, bLogEvent=True)
                elif self.logger.is_enabled():
                    self._log_exception(event)
            finally:
                if bNew and self._is_action_event(event):
                    self._action(event, crash)

        finally:
            # Postprocessing of exceptions.
            self._post_exception(event.debug.lastEvent)

    def _exception_ignored_by_default(self, event, exc_name):
        """
        Some exceptions are ignored by default.
        You can explicitly enable them again in the config file.
        """
        try:
            # This is almost identical to the exception() method.
            # The difference is the logic to determine if it's a crash.
            crash = None
            bNew = True
            try:
                if self._is_crash_event(event) and \
                        exc_name in self.options.events:
                    crash, bNew = self._add_crash(event, bLogEvent=True)
                elif self.logger.is_enabled():
                    self._log_exception(event)
            finally:
                if bNew and self._is_action_event(event):
                    self._action(event, crash)

        finally:
            # Postprocessing of exceptions.
            self._post_exception(event.debug.lastEvent)

    def unknown_exception(self, event):
        # Unknown (most likely C++) exceptions are not crashes,
        # unless explicitly overriden in the config file.
        self._exception_ignored_by_default(event, 'unknown_exception')

    def ms_vc_exception(self, event):
        # Microsoft Visual C exceptions are not crashes,
        # unless explicitly overriden in the config file.
        self._exception_ignored_by_default(event, 'ms_vc_exception')

    def breakpoint(self, event):
        """
        Breakpoint events handler
        """
        try:
            # Determine if it's the first chance exception event.
            bFirstChance = event.is_first_chance()

            # Step over breakpoints.
            # This includes both user-defined and hardcoded in the binary.
            if bFirstChance:
                event.continueStatus = win32.DBG_EXCEPTION_HANDLED

            # Determine if the breakpoint is ours.
            bOurs = hasattr(event, 'breakpoint') and event.breakpoint

            # If it's not ours, determine if it's a system breakpoint.
            # If it's ours we don't care.
            bSystem = False
            if not bOurs:
                # WOW64 breakpoints.
                bWow64 = event.get_exception_code() == \
                         win32.EXCEPTION_WX86_BREAKPOINT

                # Other system breakpoints.
                bSystem = bWow64 or \
                          event.get_process().is_system_defined_breakpoint(
                              event.get_exception_address())

            # Our breakpoints are always actionable, but only crashes if
            # explicitly stated. System breakpoints are not actionable nor
            # crashes unless explicitly stated, or overriden by the 'break_at'
            # option (in that case they become "our" breakpoints). Otherwise
            # use the same criteria as for all debug events.
            crash, bNew = None, True
            try:
                # Determine if it's a crash event.
                if bOurs or bSystem:
                    bIsCrash = 'wow64_breakpoint' in self.options.crash_events if bWow64 else 'breakpoint' in self.options.crash_events
                else:
                    bIsCrash = self._is_crash_event(event)

                # Add it as a crash if so. Always log the brief report.
                if bIsCrash:
                    crash, bNew = self._add_crash(event, bFullReport=False)

            finally:

                # Must the crash be treated as new?
                if bNew:
                    # Determine if we must take action.
                    if bOurs:
                        bAction = True
                    elif bSystem:
                        bAction = 'wow64_breakpoint' in self.options.crash_events if bWow64 else 'breakpoint' in self.options.crash_events
                    else:
                        bAction = self._is_action_event(event)

                    # If so, take action.
                    if bAction:
                        self._action(event, crash)

        finally:
            # Postprocessing of exceptions.
            self._post_exception(event.debug.lastEvent)

    def wow64_breakpoint(self, event):
        """
        WOW64 breakpoints handled by the same code as normal breakpoints.
        """
        self.breakpoint(event)
