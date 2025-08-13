import unicorn
from unicorn import unicorn_const

# from . import decompilerapi


# syscall hook
# concrete address hook
# code-symbol hook
# data-symbol hook
# skip address hook
# trace-point hook


class BaseHook:
	def __init__(self, htype: int = 0, begin: int = 0, end: int = -1):
		self.type = htype
		self.begin = begin
		self.end = end

	def handle(self):
		raise NotImplementedError


class DataSymbolHook(BaseHook):
	def __init__(self, symbol: str, size, **kwargs):
		super().__init__(**kwargs)

		address = decompilerapi.memory.resolve_symbol(symbol)
		if address is None:
			raise ValueError(
				'Symbol "%s" not found in %s' % (symbol, decompilerapi.misc.current_filename())
			)


class CodeSymbolHook(BaseHook):
	def __init__(self, symbol: str, **kwargs):
		super().__init__(**kwargs)

		address = decompilerapi.memory.resolve_symbol(symbol)
		if address is None:
			raise ValueError(
				'Symbol "%s" not found in %s' % (symbol, decompilerapi.misc.current_filename())
			)


def ios_aarch64_hooks() -> list:
	hooks = list()
	return hooks
