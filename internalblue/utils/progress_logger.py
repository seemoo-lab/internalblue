import random
import time

from internalblue.utils.logging_formatter import CustomFormatter


class ProgressLogger(object):
    spinners = [
        ['/.......', './......', '../.....', '.../....', '..../...', '...../..', '....../.',
         '.......\\', '......\\.', '.....\\..', '....\\...', '...\\....', '..\\.....', '.\\......'],
        ['|', '/', '-', '\\'],
        ['q', 'p', 'b', 'd'],
        ['.', 'o', 'O', '0', '*', ' ', ' ', ' '],
        ['▁', '▃', '▄', '▅', '▆', '▇', '█', '▇', '▆', '▅', '▄', '▃'],
        ['┤', '┘', '┴', '└', '├', '┌', '┬', '┐'],
        ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
        ['◢', '◢', '◣', '◣', '◤', '◤', '◥', '◥'],
        ['◐', '◓', '◑', '◒'],
        ['▖', '▘', '▝', '▗'],
        ['.', 'o', 'O', '°', ' ', ' ', '°', 'O', 'o', '.', ' ', ' '],
        ['<', '<', '∧', '∧', '>', '>', 'v', 'v'],
    ]

    def __init__(self, logger, msg, status, kwargs):
        self._logger = logger
        self._msg = msg
        self._status = status
        self._stopped = False
        self.last_status = 0
        self.rate = kwargs.pop('rate', 0)
        # it is a common use case to create a logger and then immediately update
        # its status line, so we reset `last_status` to accommodate this pattern
        self.last_status = 0
        self.spinner_index = 0
        self.spinner_repeat = 5
        self.spinner = self.spinners[random.randint(0, len(self.spinners) - 1)]
        # self._log(status)

    def _log(self, status):
        # this progress logger is stopped, so don't generate any more records
        if self._stopped:
            return

        if self.spinner_repeat > 0:
            self.spinner_repeat -= 1
        else:
            self.spinner_repeat = 5
            self.spinner_index = (self.spinner_index + 1) % len(self.spinner)

        msg = f'{CustomFormatter.blue}[{self.spinner[self.spinner_index]}]{CustomFormatter.reset} '

        msg += self._msg
        if msg and status:
            msg += ': '
        msg += status
        self._logger.log(CustomFormatter.PROGRESS, msg)

    def status(self, status):
        now = time.time()
        if (now - self.last_status) > self.rate:
            self.last_status = now
            self._log(status)

    def success(self, status='Done'):
        self._log(status)
        self._stopped = True

    def failure(self, status='Failed'):
        self._log(status)
        self._stopped = True

    def __enter__(self):
        return self

    def __exit__(self, exc_typ, exc_val, exc_tb):
        # if the progress logger is already stopped these are no-ops
        if exc_typ is None:
            self.success()
        else:
            self.failure()
