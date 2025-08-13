from typing import Union


class ValueStorage:
	__match_args__ = "size"

	def __init__(self, size: int):
		self.size = size
		assert size > 0, "How the fuck the size is non-positive"
		assert size <= 8, "Sizes bigger than 64 bits (8 bytes) is unsupported"


class RegisterStorage(ValueStorage):
	__match_args__ = ("name", "size")

	def __init__(self, name: str, size: int):
		super().__init__(size)
		self.name = name

	def __repr__(self):
		return 'RegisterStorage(name="%s", size=%d)' % (self.name, self.size)


class StackStorage(ValueStorage):
	__match_args__ = ("offset", "size")

	def __init__(self, offset: int, size: int):
		super().__init__(size)
		self.offset = offset

	def __repr__(self):
		return 'StackStorage(offset="%s", size=%d)' % (self.offset, self.size)


class FunctionArgument:
	__match_args__ = ("storage", "name", "index")

	def __init__(
		self, storage: Union[RegisterStorage, StackStorage], index: int, name: str | None = None
	):
		self.name = name or f"arg{index}"
		self.storage = storage
		self.index = index

	def __repr__(self):
		return "FunctionArgument(%s)" % (self.name)


class ImmediateArgument(FunctionArgument):
	__match_args__ = ("value", "storage", "index", "name")

	def __init__(
		self,
		value: int,
		storage: Union[RegisterStorage, StackStorage],
		index: int,
		name: str | None = None,
	):
		assert type(storage) in [RegisterStorage, StackStorage], (
			f"Invalid storage type: {type(storage)}"
		)

		if type(value) is not int:
			raise NotImplementedError(f"Only int values is supported, got {type(value)}")

		super().__init__(storage, index, name)
		self.value = value

	def __repr__(self):
		return "ImmediateArgument(%s, %#x)" % (self.name, self.value)

	@classmethod
	def from_function_argument(cls, arg: FunctionArgument, value: int) -> "ImmediateArgument":
		return cls(value, arg.storage, arg.index, name=arg.name)


def populate_arguments(
	arguments: tuple[FunctionArgument], values: tuple[int]
) -> list[ImmediateArgument]:
	assert len(arguments) == len(values), "Quantity of arguments and values not equal: %d vs %d" % (
		len(arguments),
		len(values),
	)

	return [
		ImmediateArgument.from_function_argument(arg, val) for (arg, val) in zip(arguments, values)
	]
