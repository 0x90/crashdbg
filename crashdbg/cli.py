import click


@click.group()
def cli():
    """
    CrashDBG - Application crash monitor and report generator
    """
    pass


@cli.command()
def run():
    """
    Run Application crash monitor
    """
    pass


@cli.command()
def report():
    """
    Generate crash report from crash DB
    """
    pass
