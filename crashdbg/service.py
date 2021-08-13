import logging
import time

from .winservice import SMWinservice


class CrashDbgService(SMWinservice):
    _svc_name_ = "CrashDbgSvc"
    _svc_display_name_ = "CrashDbg service"
    _svc_description_ = "CrashDbg service!"

    def start(self):
        self.isrunning = True

    def stop(self):
        self.isrunning = False

    def main(self):
        logging.info('Running FileMon')
        while self.isrunning:
            time.sleep(1)


def main():
    CrashDbgService.parse_command_line()


if __name__ == '__main__':
    main()
