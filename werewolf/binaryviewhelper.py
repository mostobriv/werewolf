import binaryninja
from binaryninja import VariableSourceType

from .const import (
	WW_ENDIANNESS_BIG_ENDIAN,
	WW_ENDIANNESS_LITTLE_ENDIAN,
	Architecture,
	Bitness,
	Endianness,
)

from .formalargument import FunctionArgument, RegisterStorage, StackStorage

_endianness2bn: dict[str, binaryninja.Endianness] = {
	WW_ENDIANNESS_LITTLE_ENDIAN: binaryninja.Endianness.LittleEndian,
	WW_ENDIANNESS_BIG_ENDIAN: binaryninja.Endianness.BigEndian,
}
_bn2endianness: dict[binaryninja.Endianness, str] = {v: k for (k, v) in _endianness2bn.items()}


class BinaryViewHelper:
	def __init__(self, bv: binaryninja.BinaryView):
		self.binary_view: binaryninja.BinaryView = bv

	def read_ubytelong(self, address, size, sign=False, endian=None):
		return self.read_ubitlong(address, size * 8, sign=sign, endian=endian)

	def read_ubitlong(self, address, size, sign=False, endian=None):
		if endian is not None:
			endian = _endianness2bn[endian]
		return self.binary_view.read_int(address, size, sign=sign, endian=endian)

	def read_pointer(self, address):
		return self.binary_view.read_pointer(address)

	def read_bytes(self, address, n):
		return self.binary_view.read(address, n)

	def write_ubytelong(self, address, size, value, sign=False, endian=None):
		if endian is None:
			endian = _bn2endianness[self.endianness]

		data = value.to_bytes(length=size, signed=sign, byteorder=endian)
		written = self.binary_view.write(address, data)
		assert written == size, "Failed to write %d bytes on %#x, wrote %d instead" % (
			size,
			address,
			written,
		)

		return written

	def write_byte(self, address: int, value: int, sign=False, endian=None):
		self.write_ubytelong(address, 1, value, sign, endian)

	def write_word(self, address: int, value: int, sign=False, endian=None):
		self.write_ubytelong(address, 2, value, sign, endian)

	def write_dword(self, address: int, value: int, sign=False, endian=None):
		self.write_ubytelong(address, 4, value, sign, endian)

	def write_qword(self, address: int, value: int, sign=False, endian=None):
		self.write_ubytelong(address, 8, value, sign, endian)

	def write_bytes(self, address, data):
		written = self.binary_view.write(address, data)
		assert written == len(data), "Failed to write %d bytes on %#x, wrote %d instead" % (
			len(data),
			address,
			written,
		)
		return written

	def get_func_frame_size(self, address) -> int:
		function = self.binary_view.get_function_at(address)
		if function is None:
			candidates = self.binary_view.get_functions_containing(address)
			if len(candidates) > 1:
				return None

			function = candidates[0]

		def calc_frame_size(func):
			return abs(min([v.storage for v in func.stack_layout]))

		deducted_size = calc_frame_size(function)
		return (deducted_size + 16 - 1) & ~(16 - 1)  # align to 16

	def address_is_filebacked(self, address) -> bool:
		if address < self.binary_view.start or address > self.binary_view.end:
			return False
		return not self.binary_view.is_offset_extern_semantics(address)

	def get_formal_args_of_func(self, address: int) -> list:
		arguments = list()

		func = self.binary_view.get_function_at(address)
		if func is None:
			raise ValueError(f"No function at {address:#X} found")

		for var in func.parameter_vars:
			assert var.type is not None, "Type of variable is None"

			if var.type.width <= 0 or var.type.width > 8:
				raise NotImplementedError(f"Size {var.type.width} not supported")

			match var.source_type:
				case VariableSourceType.StackVariableSourceType:
					raise NotImplementedError("TODO")
				case VariableSourceType.RegisterVariableSourceType:
					reg_name = self.binary_view.arch.get_reg_name(var.storage)
					arguments.append(
						FunctionArgument(RegisterStorage(reg_name, var.type.width), var.index)
					)
				case _:
					raise NotImplementedError

		return arguments

	@property
	def endianness(self) -> Endianness:
		return _bn2endianness[self.binary_view.endianness]

	@property
	def bitness(self) -> Bitness:
		bitness = self.binary_view.address_size << 3
		match bitness:
			case 16 | 32 | 64:
				return bitness
			case _:
				raise NotImplementedError(
					"Architectures with pointer size of %u not supported" % bitness
				)

	@property
	def arch(self) -> Architecture:
		if self.binary_view.arch.name not in ("arm", "aarch64"):
			raise NotImplementedError(
				'Architecture "%s" not supported' % self.binary_view.arch.name
			)
		return self.binary_view.arch.name

	@property
	def platform(self) -> str:
		return self.binary_view.platform.name

	@property
	def lowest_address(self) -> int:
		return self.binary_view.start

	@property
	def highest_address(self) -> int:
		return self.binary_view.end

	@property
	def page_size(self) -> int:
		return 0x1000

	@property
	def default_frame_size(self) -> int:
		return 0x1000

	@property
	def image_base(self) -> int:
		return self.lowest_address

	@property
	def stack_base(self) -> int:
		match self.bitness:
			case 32:
				return 0xEFFFF000  # highest 256mb - page
			case 64:
				return 0xFFFFFFFF00000000  # highest 512 mb - page
			case _:
				raise NotImplementedError(f"Bitness of size {self.bitness:#x} isn't supported")

	@property
	def heap_base(self) -> int:
		match self.bitness:
			case 32:
				return 0xF0000000  # highest 256MB
			case 64:
				return 0xFFFFFFFFE0000000  # highest 512MB
			case _:
				raise NotImplementedError("Bitness of size %#x isn't supported" % (self.bitness))
