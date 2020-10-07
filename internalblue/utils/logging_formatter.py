import logging


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    PROGRESS = 60

    black = "\x1b[30m"
    red = "\x1b[31m"
    green = "\x1b[32m"
    yellow = "\x1b[33m"
    blue = "\x1b[34m"
    magenta = "\x1b[35m"
    cyan = "\x1b[36m"
    white = "\x1b[37m"
    reset = "\x1b[0m"

    # "\033[F" # back to previous line
    # "\033[K" # clear line

    FORMATS = {
        logging.DEBUG: f"{yellow}[!]{reset} %(message)s",
        logging.INFO: f"{blue}[*]{reset} %(message)s",
        logging.WARNING: f"{yellow}[*]{reset} %(message)s",
        logging.ERROR: f"{red}[!]{reset} %(message)s",
        logging.CRITICAL: f"{red}[!] %(message)s{reset}",
        PROGRESS: f"\033[F\033[K%(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
