import logging
from internalblue.utils.logging_formatter import CustomFormatter


def getInternalBlueLogger() -> logging.Logger:
    logger = logging.getLogger("InternalBlue")
    logger.setLevel(logging.INFO)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    ch.setLevel(logging.INFO)
    if not logger.hasHandlers():
        logger.addHandler(ch)
    return logger
