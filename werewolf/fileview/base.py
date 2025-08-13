from abc import ABC, abstractmethod

from ..formalargument import FunctionArgument
from ..const import Endianness, Architecture, Bitness


class FileView(ABC):
	@abstractmethod
	def read_ubytelong(
		self, address: int, size: int, sign: bool = False, endian: Endianness | None = None
	) -> int: ...

	@abstractmethod
	def read_ubitlong(
		self, address: int, size: int, sign: bool = False, endian: Endianness | None = None
	) -> int: ...

	def read_byte(self, address: int, sign: bool = False, endian: Endianness | None = None) -> int:
		return self.read_ubytelong(address, 1, sign, endian)

	def read_word(self, address: int, sign: bool = False, endian: Endianness | None = None) -> int:
		return self.read_ubytelong(address, 2, sign, endian)

	def read_dword(self, address: int, sign: bool = False, endian: Endianness | None = None) -> int:
		return self.read_ubytelong(address, 4, sign, endian)

	def read_qword(self, address: int, sign: bool = False, endian: Endianness | None = None) -> int:
		return self.read_ubytelong(address, 8, sign, endian)

	@abstractmethod
	def read_pointer(self, address: int) -> int: ...

	@abstractmethod
	def read_bytes(self, address: int, n: int) -> bytes: ...

	@abstractmethod
	def write_ubytelong(self, address, size, value, sign=False, endian=None): ...

	def write_byte(self, address: int, value: int, sign=False, endian=None):
		self.write_ubytelong(address, 1, value, sign, endian)

	def write_word(self, address: int, value: int, sign=False, endian=None):
		self.write_ubytelong(address, 2, value, sign, endian)

	def write_dword(self, address: int, value: int, sign=False, endian=None):
		self.write_ubytelong(address, 4, value, sign, endian)

	def write_qword(self, address: int, value: int, sign=False, endian=None):
		self.write_ubytelong(address, 8, value, sign, endian)

	# TODO: should return number of bytes written
	@abstractmethod
	def write_bytes(self, address: int, data: bytes) -> int: ...

	@abstractmethod
	def get_func_frame_size(self, address: int) -> int | None: ...

	@abstractmethod
	def address_is_filebacked(self, address: int) -> bool: ...

	# TODO: i'm not sure if this should be in FileView abstraction level or somewhere else
	# may be i should create new abstraction for decompiler api related things
	@abstractmethod
	def get_formal_args_of_func(self, address: int) -> list[FunctionArgument]: ...

	@property
	@abstractmethod
	def bitness(self) -> Bitness: ...

	@property
	@abstractmethod
	def endianness(self) -> Endianness: ...

	@property
	@abstractmethod
	def arch(self) -> Architecture: ...

	@property
	@abstractmethod
	def lowest_address(self) -> int: ...

	@property
	@abstractmethod
	def highest_address(self) -> int: ...

	@property
	def page_size(self) -> int:
		return 0x1000

	@property
	def default_frame_size(self) -> int:
		return 0x1000

	@property
	def image_base(self) -> int:
		return self.lowest_address
		# if self.lowest_address != 0:
		# 	return self.lowest_address

		# match self.bitness:
		# 	case 16:
		# 		return 0
		# 	case 32:
		# 		return 0x10000000
		# 	case 64:
		# 		return 0x100000000
		# 	case _:
		# 		raise NotImplementedError("Bitness of size %#x isn't supported" % (self.bitness))

	@property
	def stack_base(self) -> int:
		match self.bitness:
			case 16:
				return 0x7F00
			case 32:
				return 0x7FFF0000
			case 64:
				return 0x7FFFFFFF00000000
			case _:
				raise NotImplementedError("Bitness of size %#x isn't supported" % (self.bitness))
