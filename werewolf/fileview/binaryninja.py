import binaryninja
from binaryninja import VariableSourceType

from .base import FileView


from ..const import WW_ENDIANNESS_BIG_ENDIAN, WW_ENDIANNESS_LITTLE_ENDIAN

from ..formalargument import FunctionArgument, RegisterStorage, StackStorage


class BinaryNinjaFileView(FileView):
	_endianness2bn: dict[str, binaryninja.Endianness] = {
		WW_ENDIANNESS_LITTLE_ENDIAN: binaryninja.Endianness.LittleEndian,
		WW_ENDIANNESS_BIG_ENDIAN: binaryninja.Endianness.BigEndian,
	}
	_bn2endianness: dict[binaryninja.Endianness, str] = {v: k for (k, v) in _endianness2bn.items()}

	def __init__(self, bv: binaryninja.BinaryView):
		super().__init__()
		self.__binary_view = bv

	def read_ubytelong(self, address, size, sign=False, endian=None):
		return self.read_ubitlong(address, size * 8, sign=sign, endian=endian)

	def read_ubitlong(self, address, size, sign=False, endian=None):
		if endian is not None:
			endian = self._endianness2bn[endian]
		return self.__binary_view.read_int(address, size, sign=sign, endian=endian)

	def read_pointer(self, address):
		return self.__binary_view.read_pointer(address)

	def read_bytes(self, address, n):
		return self.__binary_view.read(address, n)

	def write_ubytelong(self, address, size, value, sign=False, endian=None):
		if endian is None:
			endian = self._bn2endianness[self.endianness]

		data = value.to_bytes(length=size, signed=sign, byteorder=endian)
		written = self.__binary_view.write(address, data)
		assert written == size, "Failed to write %d bytes on %#x, wrote %d instead" % (
			size,
			address,
			written,
		)

		return written

	def write_bytes(self, address, data):
		written = self.__binary_view.write(address, data)
		assert written == len(data), "Failed to write %d bytes on %#x, wrote %d instead" % (
			len(data),
			address,
			written,
		)
		return written

	def get_func_frame_size(self, address):
		function = self.__binary_view.get_function_at(address)
		if function is None:
			candidates = self.__binary_view.get_functions_containing(address)
			if len(candidates) > 1:
				return None

			function = candidates[0]

		def calc_frame_size(func):
			return abs(min([v.storage for v in func.stack_layout]))

		deducted_size = calc_frame_size(function)
		return (deducted_size + 16 - 1) & ~(16 - 1)  # align to 16

	def address_is_filebacked(self, address):
		if address < self.__binary_view.start or address > self.__binary_view.end:
			return False
		return not self.__binary_view.is_offset_extern_semantics(address)

	def get_formal_args_of_func(self, address: int):
		arguments = list()

		func = self.__binary_view.get_function_at(address)
		if func is None:
			raise ValueError(f"No function at {address:#X} found")

		for i, var in enumerate(func.parameter_vars):
			assert i == var.index, "Variable index doesn't match the order"
			assert var.type is not None, "Type of variable is None"

			if var.type.width <= 0 or var.type.width > 8:
				raise NotImplementedError(f"Size {var.type.width} not supported")

			match var.source_type:
				case VariableSourceType.StackVariableSourceType:
					raise NotImplementedError("TODO")
				case VariableSourceType.RegisterVariableSourceType:
					reg_name = self.__binary_view.arch.get_reg_name(var.storage)
					arguments.append(
						FunctionArgument(RegisterStorage(reg_name, var.type.width), var.index)
					)
				case _:
					raise NotImplementedError

		return arguments

	@property
	def endianness(self):
		return self._bn2endianness[self.__binary_view.endianness]

	@property
	def bitness(self):
		bitness = self.__binary_view.address_size << 3
		match bitness:
			case 16 | 32 | 64:
				return bitness
			case _:
				raise NotImplementedError(
					"Architectures with pointer size of %u not supported" % bitness
				)

	@property
	def arch(self):
		if self.__binary_view.arch.name not in ("arm", "aarch64", "x86"):
			raise NotImplementedError(
				'Architecture "%s" not supported' % self.__binary_view.arch.name
			)
		return self.__binary_view.arch.name

	@property
	def lowest_address(self):
		return self.__binary_view.start

	@property
	def highest_address(self):
		return self.__binary_view.end
