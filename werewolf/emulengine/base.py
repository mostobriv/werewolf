from typing import Callable

import unicorn

from ..fileview.base import FileView
from ..memory import MemoryView, Registers
from .. import const

from enum import IntFlag


class EmulFlags(IntFlag):
	LAZY_MEM_LOADING = 1 << 0
	TRACE_INSTRUCTIONS = 1 << 32


class Options:
	def __init__(self) -> None:
		self.unicorn_options: int = 0
		self.ei_options: EmulFlags = 0


class EmulationEngine:
	_regs: dict[str, int] = None
	arch_helper = None

	def __init__(self, fv: FileView, options: int = 0):
		options |= const.endianness2uc[fv.endianness]

		self.uc = unicorn.Uc(const.arch2uc[fv.arch], options)
		self.fv = fv
		self.mem = MemoryView(self.uc, fv, Registers(self._regs))
		self.user_data = {"self": self, "mem": self.mem, "fv": self.fv}
		self.__pre_emulation_routines: list[Callable[["EmulationEngine"], None]] = list()
		self.__post_emulation_routines: list[Callable[["EmulationEngine"], None]] = list()

		self.add_hook(
			unicorn.UC_HOOK_MEM_READ_UNMAPPED
			| unicorn.UC_HOOK_MEM_WRITE_UNMAPPED
			| unicorn.UC_HOOK_MEM_FETCH_UNMAPPED,
			self.mem.handle_memory_fault,
			user_data=self.user_data,
		)

	def add_hook(self, hook_type: int, hook_handler: Callable, user_data: dict | None = None):
		if user_data is None:
			user_data = self.user_data
		else:
			for key in ["self", "mem", "fv"]:
				if key in user_data:
					print(f"{key} used in user_data, however it's reserved, overwritten")

			user_data.update(self.user_data)

		self.uc.hook_add(hook_type, hook_handler, user_data=user_data)

	def stop_emulation(self):
		# Not wrapping it in try-except to get example of case when emulation can't be done properly
		self.uc.emu_stop()

	def emulate_range(self, begin: int, until: int, timeout: int = 0, count: int = 0):
		self.run_pre_emulation_routines()

		print("Emulating range %#x - %#x" % (begin, until))

		self.uc.emu_start(begin, until, timeout, count)

		self.run_post_emulation_routines()

	def run_pre_emulation_routines(self) -> None:
		for routine in self.__pre_emulation_routines:
			routine(self)

	def run_post_emulation_routines(self) -> None:
		for routine in self.__post_emulation_routines:
			routine(self)

	def add_pre_emulation_routine(
		self, routine: Callable[["EmulationEngine"], None] | None = None
	) -> None:
		if routine is not None:
			self.__pre_emulation_routines.append(routine)

	def add_post_emulation_routine(
		self, routine: Callable[["EmulationEngine"], None] | None = None
	) -> None:
		if routine is not None:
			self.__post_emulation_routines.append(routine)

	def setup_stackframe(self, address: int | None = None, size_hint: int | None = None):
		raise NotImplementedError

	def skip_instruction(self):
		raise NotImplementedError

	def reset_memory(self):
		for region in self.uc.mem_regions():
			self.uc.mem_unmap(region[0], region[1] - region[0] + 1)
