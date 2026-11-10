"""Keep request targets and credentials out of server exception/parser logs."""
from gunicorn.glogging import Logger

class RedactedLogger(Logger):
    def access(self, response, request, environ, request_time):
        pass

    def warning(self, message, *args, **kwargs):
        self.error_log.warning('HTTP server warning; request details suppressed')

    def error(self, message, *args, **kwargs):
        self.error_log.error('HTTP server error; request details suppressed')

    def exception(self, message, *args, **kwargs):
        self.error_log.error('HTTP server exception; request details suppressed')

    def critical(self, message, *args, **kwargs):
        self.error_log.critical('HTTP server critical error; request details suppressed')
