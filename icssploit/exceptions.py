import logging


LOGGER = logging.getLogger(__name__)


class icssploitException(Exception):
    def __init__(self, msg=''):
        super(icssploitException, self).__init__(msg)
        LOGGER.exception(self)


class OptionValidationError(icssploitException):
    pass


class StopThreadPoolExecutor(icssploitException):
    pass
