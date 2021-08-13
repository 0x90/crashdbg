import re


def _parse_list(value):
    return set([token.strip() for token in value.lower().split(',')])


def _parse_boolean(value):
    value = value.strip().lower()

    if value in ['true', 'yes', 'y']:
        return True

    if value in ['false', 'no', 'n']:
        return False

    return bool(int(value))


class Options(object):
    """
    Options object with its default settings.
    """
    def __init__(self):
        # Targets
        self.attach = list()
        self.console = list()
        self.windowed = list()
        self.service = list()

        # List options
        self.action = list()
        self.break_at = list()
        self.stalk_at = list()

        # Tracing options
        self.pause = False
        self.interactive = False
        self.time_limit = 0
        self.echo = False
        self.action_events = ['exception', 'output_string']
        self.crash_events = ['exception', 'output_string']

        # Debugging options
        self.autodetach = True
        self.hostile = False
        self.follow = True
        self.restart = False

        # Output options
        self.verbose = True
        self.ignore_errors = False
        self.logfile = None
        self.database = None
        self.duplicates = True
        self.firstchance = False
        self.memory = 0

    def read_config_file(self, config):
        """
        Read the configuration file
        """
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
                        self.attach.append(value)
                elif key == 'console':
                    if value:
                        self.console.append(value)
                elif key == 'windowed':
                    if value:
                        self.windowed.append(value)
                elif key == 'service':
                    if value:
                        self.service.append(value)

                # List options
                elif key == 'break_at':
                    self.break_at.extend(_parse_list(value))
                elif key == 'stalk_at':
                    self.stalk_at.extend(_parse_list(value))
                elif key == 'action':
                    self.action.append(value)

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
                        self.verbose = _parse_boolean(value)
                    elif key == 'logfile':
                        self.logfile = value
                    elif key == 'database':
                        self.database = value
                    elif key == 'duplicates':
                        self.duplicates = _parse_boolean(value)
                    elif key == 'firstchance':
                        self.firstchance = _parse_boolean(value)
                    elif key == 'memory':
                        self.memory = int(value)
                    elif key == 'ignore_python_errors':
                        self.ignore_errors = _parse_boolean(value)

                    # Debugging options
                    elif key == 'hostile':
                        self.hostile = _parse_boolean(value)
                    elif key == 'follow':
                        self.follow = _parse_boolean(value)
                    elif key == 'autodetach':
                        self.autodetach = _parse_boolean(value)
                    elif key == 'restart':
                        self.restart = _parse_boolean(value)

                    # Tracing options
                    elif key == 'pause':
                        self.pause = _parse_boolean(value)
                    elif key == 'interactive':
                        self.interactive = _parse_boolean(value)
                    elif key == 'time_limit':
                        self.time_limit = int(value)
                    elif key == 'echo':
                        self.echo = _parse_boolean(value)
                    elif key == 'action_events':
                        self.action_events = _parse_list(value)
                    elif key == 'crash_events':
                        self.crash_events = _parse_list(value)

                    # Unknown option
                    else:
                        msg = ("unknown option %s in line %d"
                               " of config file %s") % (key, number, config)
                        raise RuntimeError(msg)

        # Return the options object
        return self
