from typing import Any, Union

import unicorn

from collections.abc import Callable

from .fileview.base import FileView
from .emulengine import aarch64, base
from . import util

from .formalargument import populate_arguments, RegisterStorage, StackStorage, ImmediateArgument


def arm64_initialize_arguments(engine: base.EmulationEngine, arguments: list[ImmediateArgument]):
	for arg in arguments:
		match arg.storage:
			case RegisterStorage(name):
				print("%s = %#x" % (name, arg.value))
				engine.mem.write_reg(engine.mem.regs[name], arg.value)

			case StackStorage(offset, size):
				sp_value = engine.mem.read_reg(engine.mem.regs.sp)
				engine.mem.write_ubytelong(sp_value + offset, arg.value, size)

			case _:
				raise TypeError("Invalid type of storage: %s" % type(arg.storage))


def run_emulate_function(
	file_view: FileView,
	function_address: int,
	arguments: Union[tuple[int], tuple[ImmediateArgument]] | None = None,
	timeout: int = 0,
	count: int = 0,
	pre_emulation_routine: Callable | None = None,
	post_emulation_routine: Callable | None = None,
) -> base.EmulationEngine:
	if type(arguments[0]) is int:
		formal_args = file_view.get_formal_args_of_func(function_address)
		arguments = populate_arguments(formal_args, arguments)

	engine = native_emulation_engine(file_view)
	engine.add_pre_emulation_routine(lambda eng: arm64_initialize_arguments(eng, arguments))
	engine.add_pre_emulation_routine(pre_emulation_routine)
	engine.add_post_emulation_routine(post_emulation_routine)

	begin = function_address
	until = util.max_num_of_size(file_view.bitness)

	def depth_accounting_hook(uc: unicorn.Uc, address: int, size: int, user_data: dict):
		engine = user_data["self"]
		mem = user_data["mem"]

		opcode = mem.read_dword(address, endian="little")
		if engine.arch_helper.is_return(opcode):
			user_data["stack"] -= 1
			if user_data["stack"] <= 0:
				engine.stop_emulation()

		elif engine.arch_helper.is_call(opcode):
			user_data["stack"] += 1

	engine.add_hook(unicorn.UC_HOOK_CODE, depth_accounting_hook, user_data={"stack": 1})
	engine.emulate_range(begin, until, timeout, count)

	return engine


def run_emulate_until_return(
	file_view: FileView,
	address: int,
	timeout: int = 0,
	count: int = 0,
	pre_emulation_routine: Callable | None = None,
	post_emulation_routine: Callable | None = None,
) -> base.EmulationEngine:
	engine = native_emulation_engine(file_view)
	engine.add_pre_emulation_routine(pre_emulation_routine)
	engine.add_post_emulation_routine(post_emulation_routine)

	begin = address
	until = util.max_num_of_size(file_view.bitness)

	def depth_accounting_hook(uc: unicorn.Uc, address: int, size: int, user_data: dict):
		engine = user_data["self"]
		mem = user_data["mem"]

		opcode = mem.read_dword(address, endian="little")
		if engine.arch_helper.is_return(opcode):
			user_data["stack"] -= 1
			if user_data["stack"] <= 0:
				engine.stop_emulation()

		elif engine.arch_helper.is_call(opcode):
			user_data["stack"] += 1

	engine.add_hook(unicorn.UC_HOOK_CODE, depth_accounting_hook, user_data={"stack": 1})
	engine.emulate_range(begin, until, timeout, count)

	return engine


def run_emulate_range(
	file_view: FileView,
	begin: int,
	until: int,
	timeout: int = 0,
	count: int = 0,
	should_init_frame: bool = True,
	pre_emulation_routine: Callable | None = None,
	post_emulation_routine: Callable | None = None,
) -> base.EmulationEngine:
	"""
	Emulate chosen range of memory. Range end boundary is excluded - [begin:end).

	Parameters
	----------
	begin: int
		Starting address (address in decompiler, it may change if binary is PIE) of range
	until: int
		Final address (address in decompiler, it may change if binary is PIE) of range
	count: int, optional
		Total number of instructions to emulate (default is None)
	should_init_frame: bool, optional
		Should engine initialize stack frame for chosen range or not. (default True)
	pre_emulation_routine: function, optional
		Function that is called before the emulation starts.
	post_emulation_routine: function, optional
		Function that is called after the emulation ends.
	"""

	engine = native_emulation_engine(file_view)

	if should_init_frame:
		engine.setup_stackframe(begin)

	engine.add_pre_emulation_routine(pre_emulation_routine)
	engine.add_post_emulation_routine(post_emulation_routine)

	engine.emulate_range(begin, until, timeout, count)

	return engine


def native_emulation_engine(fv: FileView) -> base.EmulationEngine:
	arch = fv.arch

	if arch != "aarch64":
		raise NotImplementedError("Architecture %s isn't supported yet" % arch)

	return aarch64.Aarch64EmulationEngine(fv)


# def code_hook(uc, address, size, user_data) -> bool:
# 	print("[*] Code hook: %#x -> %#x" % (address, user_data["self"].mem.read_dword(address)))
# 	if user_data["self"].mem.read_dword(address) == 0xd65f03c0:
# 		uc.emu_stop()
