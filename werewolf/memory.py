from typing import Iterator, Dict

import unicorn
import sys
import traceback

from .fileview.base import FileView


class Registers:
	def __init__(self, regs2ucregs: Dict[str, int]) -> None:
		self.__regs_translation = regs2ucregs

	def __getattr__(self, register_name: str) -> int:
		return self.__regs_translation[register_name.upper()]

	def __getitem__(self, register_name: str) -> int:
		return self.__regs_translation[register_name.upper()]


class MemoryView:
	def __init__(self, uc: unicorn.Uc, file_view: FileView, regs: Registers, strict: bool = False):
		self.uc = uc
		self.fv = file_view
		self.regs = regs
		# self.strict = strict # TODO

	def write_ubytelong(self, addr: int, val: int, size: int = 4):
		self.uc.mem_write(addr, val.to_bytes(size, self.fv.endianness))

	def write_byte(self, addr: int, val: int):
		self.write_ubytelong(addr, val, 1)

	def write_word(self, addr: int, val: int):
		self.write_ubytelong(addr, val, 2)

	def write_dword(self, addr: int, val: int):
		self.write_ubytelong(addr, val, 4)

	def write_qword(self, addr: int, val: int):
		self.write_ubytelong(addr, val, 8)

	def write_bytes(self, addr: int, data: bytes):
		self.uc.mem_write(addr, data)

	def read_ubytelong(self, addr: int, size: int = 4, endian: str | None = None) -> int:
		data = self.uc.mem_read(addr, size)
		if endian is None:
			endian = self.fv.endianness
		return int.from_bytes(data, endian)

	def read_byte(self, address: int, endian: str | None = None) -> int:
		return self.read_ubytelong(address, 1, endian=endian)

	def read_word(self, address: int, endian: str | None = None) -> int:
		return self.read_ubytelong(address, 2, endian=endian)

	def read_dword(self, address: int, endian: str | None = None) -> int:
		return self.read_ubytelong(address, 4, endian=endian)

	def read_qword(self, address: int, endian: str | None = None) -> int:
		return self.read_ubytelong(address, 8, endian=endian)

	def read_bytes(self, address: int, size: int) -> bytes:
		return self.uc.mem_read(address, size)

	def read_cstr(self, addr: int, max_size: int = 128) -> bytes:
		offset = 0
		current_byte = self.read_byte(addr)
		# FIXME: dont fucking know how to concat damn bytes
		cstr = [current_byte]

		while current_byte != 0 and offset < max_size:
			offset += 1
			current_byte = self.read_byte(addr + offset)
			cstr.append(
				current_byte
			)  # doesn't matter what endianness we used as there is just 1 byte length

		return bytes(cstr[:-1])

	def read_reg(self, reg_id: int) -> int:
		return self.uc.reg_read(reg_id)

	def write_reg(self, reg_id: int, value: int) -> None:
		return self.uc.reg_write(reg_id, value)

	def range2page(self, start: int, end: int) -> tuple[int, int]:
		PAGE_SIZE = self.fv.page_size
		return start & ~(PAGE_SIZE - 1), (end & ~(PAGE_SIZE - 1)) + PAGE_SIZE

	def handle_memory_fault(
		self, uc: unicorn.Uc, access: int, address: int, size: int, value, user_data
	) -> bool:
		print("[!] Memory fault at %#x" % (address))
		try:
			uc.mem_map(self.addr2page(address), self.fv.page_size)

			if self.fv.address_is_filebacked(address):
				print(
					"[!] Memory is backed by file, hotloading %#x - %#x"
					% (self.addr2page(address), self.addr2page(address) + self.fv.page_size)
				)

				raw_data = self.fv.read_bytes(self.addr2page(address), self.fv.page_size)
				uc.mem_write(self.addr2page(address), raw_data)
		except Exception:
			traceback.print_exc(file=sys.stdout)
			raise

		return True

	def memory_regions(self) -> Iterator[tuple[int, int, int]]:
		return self.uc.mem_regions()

	def addr2page(self, addr: int) -> int:
		return addr & ~(self.fv.page_size - 1)
