from typing import Any, Callable, overload

import unicorn

from collections import defaultdict

import binaryninja

from ..binaryviewhelper import BinaryViewHelper
from ..memory import MemoryView, Registers
from ..common import logger
from .. import const


from dataclasses import dataclass, field
from enum import IntFlag


@dataclass
class EmulationContext:
	engine: "EmulationEngine"
	memory_view: MemoryView
	binary_view_helper: BinaryViewHelper
	extra_data: dict = field(default_factory=dict)


class EmulFlags(IntFlag):
	LAZY_MEM_LOADING = 1 << 0
	TRACE_INSTRUCTIONS = 1 << 32


class Options:
	def __init__(self) -> None:
		self.unicorn_options: int = 0
		self.ei_options: EmulFlags = 0


def function_hook(func, symbol: tuple[str]):
	logger = binaryninja.Logger(0, "FunctionHook")

	from functools import wraps

	@wraps(func)
	def inner_wrapper(*args, **kwargs):
		retval = func(*args, **kwargs)
		logger.log_debug(f"Emulated {func.__name__}(...) -> {retval}")

	return inner_wrapper


class CodeHookManager:
	HookSubstitute = Callable[[EmulationContext], bool]

	def __init__(self, bvh: BinaryViewHelper):
		self.bvh = bvh
		self.hooks = defaultdict(list)
		self.logger = binaryninja.Logger(0, "FunctionHook")

	@overload
	def register_hook(self, address: int, sub: HookSubstitute): ...

	@overload
	def register_hook(self, address: list[int], sub: HookSubstitute): ...

	def register_hook(self, _address: int | list[int], sub: HookSubstitute):
		addresses: list
		if isinstance(_address, int):
			addresses = [_address]
		elif isinstance(_address, list):
			addresses = _address
		else:
			assert False, f"Wrong symbol type ({type(_address)}), must be int or list[int]"

		for addr in addresses:
			if not self.bvh.binary_view.is_offset_executable(addr):
				continue

			self.hooks[addr].append(sub)

	def dispatch_hook(self, uc: unicorn.Uc, address: int, size: int, ctx: EmulationContext):
		if address not in self.hooks:
			return

		substitutes = self.hooks[address]

		for substitute in substitutes:
			if substitute(ctx):
				break

		ctx.engine.emul_return()


# def trace_instructions(uc: unicorn.Uc, address: int, size: int, user_data: Any):
# 	binaryninja.log.log_debug(f"{address:#X}")


class EmulationEngine:
	_regs: dict[str, int] = None
	arch_helper = None

	def __init__(
		self,
		bvh: BinaryViewHelper,
		code_hook_manager: CodeHookManager,
		pre_emulation_routines: list[Callable] = None,
		post_emulation_routines: list[Callable] = None,
		options: int = 0,
	):
		options |= const.endianness2uc[bvh.endianness]

		self.uc = unicorn.Uc(const.arch2uc[bvh.arch], options)
		self.bvh = bvh
		self.mem = MemoryView(self.uc, bvh, Registers(self._regs))
		self.code_hook_manager: CodeHookManager = code_hook_manager
		self.__pre_emulation_routines: list[Callable[["EmulationEngine"], None]] = list()
		self.__post_emulation_routines: list[Callable[["EmulationEngine"], None]] = list()

		if pre_emulation_routines is not None:
			self.__pre_emulation_routines = pre_emulation_routines

		if post_emulation_routines is not None:
			self.__post_emulation_routines = post_emulation_routines

		self.add_raw_hook(
			unicorn.UC_HOOK_MEM_READ_UNMAPPED
			| unicorn.UC_HOOK_MEM_WRITE_UNMAPPED
			| unicorn.UC_HOOK_MEM_FETCH_UNMAPPED,
			self.mem.handle_memory_fault,
		)

		self.add_raw_hook(unicorn.UC_HOOK_CODE, self.code_hook_manager.dispatch_hook)

	def add_raw_hook(self, hook_type: int, hook_handler: Callable, user_data: dict | None = None):
		ctx = EmulationContext(engine=self, memory_view=self.mem, binary_view_helper=self.bvh)

		if user_data is not None:
			ctx.extra_data = user_data

		self.uc.hook_add(hook_type, hook_handler, user_data=ctx)

	def add_code_hook(self, address: int | list[int], substitute: Callable):
		self.code_hook_manager.register_hook(address, substitute)

	def stop_emulation(self):
		# Not wrapping it in try-except to get example of case when emulation can't be done properly
		self.uc.emu_stop()

	def emulate_range(self, begin: int, until: int, timeout: int = 0, count: int = 0):
		self.run_pre_emulation_routines()

		logger.info(f"Emulating range {begin:#x} - {until:#x}")

		self.uc.emu_start(begin, until, timeout, count)

		self.run_post_emulation_routines()

	def emulate_until_return(self, begin: int, timeout: int = 0, count: int = 0):
		def depth_accounting_hook(uc: unicorn.Uc, address: int, size: int, ctx: EmulationContext):
			logger.info(f"{address:#x}")

			engine = ctx.engine
			mem = ctx.memory_view
			stack = ctx.extra_data["stack"]

			opcode = mem.read_dword(address, endian="little")
			if engine.arch_helper.is_return(opcode):
				stack -= 1
				if stack <= 0:
					engine.stop_emulation()

			elif engine.arch_helper.is_call(opcode):
				stack += 1

		self.run_pre_emulation_routines()

		logger.info(f"Emulating until return, starting at {begin:#x}")

		self.add_raw_hook(unicorn.UC_HOOK_CODE, depth_accounting_hook, {"stack": 1})

		self.uc.emu_start(begin, 0x100000000, timeout, count)

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

	def reset_memory(self):
		for region in self.uc.mem_regions():
			self.uc.mem_unmap(region[0], region[1] - region[0] + 1)

	def init_stack(self):
		# Allocating 256 kb of stack
		# TODO: add fallback to allocate additional stack space, when needed
		self.uc.mem_map(
			self.bvh.stack_base - 256 * self.bvh.page_size,
			256 * self.bvh.page_size,
			unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
		)
		self.uc.reg_write(self.mem.regs.sp, self.bvh.stack_base)

		# TODO: move it somewhere else
		# Allocating page-guard
		self.uc.mem_map(self.bvh.stack_base, self.bvh.page_size, unicorn.UC_PROT_NONE)

	def builder(self):
		raise NotImplementedError

	# Target dependent
	def setup_stackframe(self, address: int | None = None, size_hint: int | None = None):
		raise NotImplementedError

	# Target dependent
	def skip_instruction(self):
		raise NotImplementedError

	# Target dependent
	def emul_return(self):
		raise NotImplementedError
