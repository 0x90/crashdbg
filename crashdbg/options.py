
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
