import binaryninja


class Logger:
	def __init__(self, name: str):
		self._logger = binaryninja.Logger(0, name)

	def debug(self, message: str):
		self._logger.log_debug(message)

	def info(self, message: str):
		self._logger.log_debug(message)

	def warning(self, message: str):
		self._logger.log_warn(message)

	def error(self, message: str, exception: Exception = None):
		if exception is None:
			self._logger.log_error(message)
		else:
			self._logger.log_error_for_exception(message)
