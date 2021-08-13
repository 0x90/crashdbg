"""'
SMWinservice
by Davide Mastromatteo

Base class to create winservice in Python
-----------------------------------------

Instructions:

1. Just create a new class that inherits from this base class
2. Define into the new class the variables
   _svc_name_ = "nameOfWinservice"
   _svc_display_name_ = "name of the Winservice that will be displayed in scm"
   _svc_description_ = "description of the Winservice that will be displayed in scm"
3. Override the three main methods:
    def start(self) : if you need to do something at the service initialization.
                      A good idea is to put here the inizialization of the running condition
    def stop(self)  : if you need to do something just before the service is stopped.
                      A good idea is to put here the invalidation of the running condition
    def main(self)  : your actual run loop. Just create a loop based on your running condition
4. Define the entry point of your module calling the method "parse_command_line" of the new class
5. Enjoy
"""
import os
import time
import socket
import logging

import pywintypes
import servicemanager
import win32event
import win32service
import win32serviceutil


class SMWinservice(win32serviceutil.ServiceFramework):
    """Base class to create winservice in Python"""

    _svc_name_ = 'pythonService'
    _svc_display_name_ = 'Python Service'
    _svc_description_ = 'Python Service Description'

    @classmethod
    def parse_command_line(cls):
        """
        ClassMethod to parse the command line
        """
        win32serviceutil.HandleCommandLine(cls)

    def __init__(self, args):
        """
        Constructor of the winservice
        """
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        """
        Called when the service is asked to stop
        """
        self.stop()
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        """
        Called when the service is asked to start
        """
        self.start()
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def start(self):
        """
        Override to add logic before the start
        eg. running condition
        """
        pass

    def stop(self):
        """
        Override to add logic before the stop
        eg. invalidating running condition
        """
        pass

    def main(self):
        """
        Main class to be overridden to add logic
        """
        pass

    @classmethod
    def setup(cls, cmd, user=None, password=None, startup='manual', cwd=None, wait=0):
        # from gramex.config import logging
        name, service_name = cls._svc_display_name_, cls._svc_name_
        port = getattr(cls, '_svc_port_', None)
        if cwd is None:
            cwd = os.getcwd()
        info = (name, cwd, 'port %s' % port if port is not None else '')
        service_class = win32serviceutil.GetServiceClassString(cls)
        startup = cls.startup_map[startup]
        running = win32service.SERVICE_RUNNING
        if cmd[0] == 'install':
            win32serviceutil.InstallService(
                service_class, service_name, displayName=name, description=cls._svc_description_,
                startType=startup, userName=user, password=password)
            win32serviceutil.SetServiceCustomOption(cls._svc_name_, 'cwd', cwd)
            logging.info('Installed service. %s will run from %s %s' % info)
        elif cmd[0] in {'update', 'change'}:
            win32serviceutil.ChangeServiceConfig(
                service_class, service_name, displayName=name, description=cls._svc_description_,
                startType=startup, userName=user, password=password)
            win32serviceutil.SetServiceCustomOption(cls._svc_name_, 'cwd', cwd)
            logging.info('Updated service. %s will run from %s %s' % info)
        elif cmd[0] in {'remove', 'uninstall'}:
            try:
                win32serviceutil.StopService(service_name)
            except pywintypes.error as e:
                if e.args[0] != winerror.ERROR_SERVICE_NOT_ACTIVE:
                    raise
            win32serviceutil.RemoveService(service_name)
            logging.info('Removed service. %s ran from %s %s' % info)
        elif cmd[0] == 'start':
            win32serviceutil.StartService(service_name, cmd[1:])
            if wait:
                win32serviceutil.WaitForServiceStatus(service_name, running, wait)
            logging.info('Started service %s at %s %s' % info)
        elif cmd[0] == 'stop':
            if wait:
                win32serviceutil.StopServiceWithDeps(service_name, waitSecs=wait)
            else:
                win32serviceutil.StopService(service_name)
            logging.info('Stopped service %s at %s %s' % info)
        elif cmd[0]:
            logging.error('Unknown command: %s' % cmd[0])


class CrashDbgService(SMWinservice):
    _svc_name_ = "CrashDbgSvc"
    _svc_display_name_ = "CrashDbg service"
    _svc_description_ = "CrashDbg service!"

    def start(self):
        self.isrunning = True

    def stop(self):
        self.isrunning = False

    def main(self):
        logging.info('Running CrashDbg service')
        while self.isrunning:
            time.sleep(1)


def main():
    CrashDbgService.parse_command_line()


if __name__ == '__main__':
    main()
