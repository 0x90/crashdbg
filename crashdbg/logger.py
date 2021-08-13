import logging
import sys
from datetime import datetime
from time import time
import coloredlogs

LOG_FORMAT = '%(asctime)s-[%(name)-7s]- %(levelname)-7s %(message)s'
LOG_FIELD_STYLES = {'asctime': {},
                    'hostname': {},
                    'levelname': {'bold': True},
                    'name': {},
                    'programname': {}}
LOG_FILENAME = 'crashdbg_' + datetime.fromtimestamp(time()).strftime('%Y_%m_%d %H_%M_%S') + ".log"


def create_logger(name=None,
                  level=logging.INFO,
                  filename=LOG_FILENAME):
    formatter = logging.Formatter('%(levelname)s : %(asctime)s : %(name)s : %(message)s')
    fileHandler = logging.FileHandler(filename)
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(fileHandler)
    logger.addHandler(streamHandler)
    coloredlogs.install(level=level, )
    return logger


def setup_main_logger(name, level=logging.INFO):
    _reset_all_loggers()
    # _set_basil_logger_to(logging.WARNING)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    _setup_coloredlogs(logger)
    _add_success_level(logger)
    _add_logfiles_to(logger)
    return logger


def setup_derived_logger(name, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    _setup_coloredlogs(logger)
    _add_success_level(logger)
    _add_logfiles_to(logger)
    return logger


def setup_logfile(filename, level=logging.INFO):
    fh = logging.FileHandler(filename)
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter(LOG_FORMAT))

    # Add filehandler to all active loggers
    for lg in logging.Logger.manager.loggerDict.values():
        if isinstance(lg, logging.Logger):
            lg.addHandler(fh)

    return fh


def close_logfile(fh):
    for lg in logging.Logger.manager.loggerDict.values():
        if isinstance(lg, logging.Logger):
            lg.removeHandler(fh)


def _add_logfiles_to(logger):
    fhs = []
    for lg in logging.Logger.manager.loggerDict.values():
        if isinstance(lg, logging.Logger):
            for handler in lg.handlers[:]:
                if isinstance(handler, logging.FileHandler):
                    fhs.append(handler)

    map(logger.addHandler, fhs)


def _setup_coloredlogs(logger, format=LOG_FORMAT):
    loglevel = logger.getEffectiveLevel()
    coloredlogs.DEFAULT_FIELD_STYLES = LOG_FIELD_STYLES
    coloredlogs.DEFAULT_LOG_LEVEL = loglevel
    # coloredlogs.install(fmt=FORMAT, milliseconds=True, loglevel=loglevel)
    coloredlogs.install(fmt=format, loglevel=loglevel)


def _add_success_level(logger):
    # WARNING(30) > SUCCESS(25) > INFO(20)
    logging.SUCCESS = 25
    logging.addLevelName(logging.SUCCESS, 'SUCCESS')
    logger.success = lambda msg, *args, **kwargs: logger.log(logging.SUCCESS, msg, *args, **kwargs)


def _reset_all_loggers():
    logging.root.handlers = []
