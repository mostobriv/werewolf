import binaryninja
from binaryninja import MediumLevelILOperation, HighLevelILOperation
from binaryninjaui import UIContext

from . import formalargument
from . import emu

from .emulengine.base import EmulationEngine, CodeHookManager
from .emulengine.aarch64 import Aarch64EmulationEngine
from .binaryviewhelper import BinaryViewHelper

from typing import Callable, overload


def _get_current_binary_view() -> binaryninja.BinaryView:
	# TODO: wrap it in try-except, but for now i need to get the example of possible exception
	return UIContext.activeContext().getCurrentView().getData()


def run_emulate_llil_call(
	instr: binaryninja.LowLevelILInstruction, bv: binaryninja.BinaryView | None = None
) -> EmulationEngine:
	raise NotImplementedError("I had no ideas of how to implement this at the moment")


def run_emulate_mlil_call(
	instr: binaryninja.MediumLevelILInstruction, bv: binaryninja.BinaryView | None = None
) -> EmulationEngine:
	if instr.operation != MediumLevelILOperation.MLIL_CALL:
		raise ValueError(f"Expected MediumLevelILCall, got {instr}")

	if bv is None:
		bv = _get_current_binary_view()

	target_func_addr = instr.dest.constant

	bvhelper = BinaryViewHelper(bv)
	formal_args = bvhelper.get_formal_args_of_func(target_func_addr)
	values = list()

	for param in instr.params:
		# TODO: need to get cases when pvs is set to const, but instruction in params isn't const,
		# thus there will be prerequisites to do lookup into pvs.
		if not isinstance(param, binaryninja.MediumLevelILConstBase):
			raise NotImplementedError(
				f"Currently only const mlil instructions is supported, got {param}"
			)

		match param.operation:
			case MediumLevelILOperation.MLIL_CONST:
				values.append(param.constant)
			case MediumLevelILOperation.MLIL_CONST_PTR:
				values.append(param.constant)
			case MediumLevelILOperation.MLIL_FLOAT_CONST:
				raise NotImplementedError
			case MediumLevelILOperation.MLIL_CONST_DATA:
				raise NotImplementedError
			case _:
				raise ValueError("wtf?")

	concrete_args = formalargument.populate_arguments(formal_args, values)
	return emu.run_emulate_function(bvhelper, target_func_addr, concrete_args)


def run_emulate_hlil_call(
	instr: binaryninja.HighLevelILInstruction, bv: binaryninja.BinaryView | None = None
) -> EmulationEngine:
	if instr.operation != HighLevelILOperation.HLIL_CALL:
		raise ValueError(f"Expected HighLevelILLevelILCall, got {instr}")

	if bv is None:
		bv = _get_current_binary_view()

	target_func_addr = instr.dest.constant

	bvhelper = BinaryViewHelper(bv)
	formal_args = bvhelper.get_formal_args_of_func(target_func_addr)
	values = list()

	for param in instr.params:
		# TODO: need to get cases when pvs is set to const, but instruction in params isn't const,
		# thus there will be prerequisites to do lookup into pvs.
		if not isinstance(param, binaryninja.Constant):
			raise NotImplementedError(
				f"Currently only const hlil instructions is supported, got {param}"
			)

		match param.operation:
			case HighLevelILOperation.HLIL_CONST:
				values.append(param.constant)
			case HighLevelILOperation.HLIL_CONST_PTR:
				values.append(param.constant)
			case HighLevelILOperation.HLIL_FLOAT_CONST:
				raise NotImplementedError
			case HighLevelILOperation.HLIL_CONST_DATA:
				raise NotImplementedError
			case _:
				raise ValueError("wtf?")

	concrete_args = formalargument.populate_arguments(formal_args, values)
	return emu.run_emulate_function(bvhelper, target_func_addr, concrete_args)


def run_emulate_function(function: binaryninja.Function, arguments: list) -> EmulationEngine:
	bv = function.view
	assert bv is not None


class alloc:
	__match_args__ = ("size",)

	def __init__(self, size: int):
		self.size = size


class ArgumentInitializer:
	def __init__(self, function: binaryninja.Function, arguments: list):
		self.function: binaryninja.Function = function
		self.arguments: list = arguments

	def __call__(self, engine: EmulationEngine):
		assert len(self.arguments) == len(self.function.parameter_vars), (
			"provided arguments length not equal to function parameters"
		)

		engine.init_stack()

		for i, arg in enumerate(self.arguments):
			match arg:
				case int(x):
					engine.mem.write_reg(engine.mem.regs.x0 + i, x)

				case alloc(size):
					size = size if size % 16 == 0 else (size // 16 + 1) * 16
					ptr = engine.mem.read_reg(engine.mem.regs.sp) - size

					print(f"Allocated {size} bytes at {ptr}")

					# idk, just sub another 16 to be extra safe
					engine.mem.write_reg(engine.mem.regs.sp, ptr - 16)
					engine.mem.write_reg(engine.mem.regs.x0 + i, ptr)

				case _:
					raise NotImplementedError(f"Unsupported type: {type(arg)}")


def run_emulate_function_at(
	address: int, arguments: list, bv: binaryninja.BinaryView | None = None
):
	function = bv.get_function_at(address)

	engine = (
		EmulationEngineBuilder()
		.binary_view(function.view)
		.pre_emulation_routine(ArgumentInitializer(function, arguments))
		.build()
	)

	engine.emulate_until_return(address)

	return engine

	# engine.emulate_range(
	# 	function.start,
	# 	-1,
	# )


class EmulationEngineBuilder:
	def __init__(self):
		self.bv: binaryninja.BinaryView = None
		self.hooks: list[tuple] = list()
		self._pre_emulation_routines: list[Callable] = list()
		self._post_emulation_routines: list[Callable] = list()

	def binary_view(self, bv: binaryninja.BinaryView) -> "EmulationEngineBuilder":
		self.bv = bv
		return self

	def code_hook(self, addr: int | list[int], substitute) -> "EmulationEngineBuilder":
		self.hooks.append((addr, substitute))
		return self

	def pre_emulation_routine(self, routine: Callable) -> "EmulationEngineBuilder":
		self._pre_emulation_routines.append(routine)
		return self

	def pre_emulation_routines(self, routines: list[Callable]) -> "EmulationEngineBuilder":
		self._pre_emulation_routines.extend(routines)
		return self

	def post_emulation_routine(self, routine: Callable) -> "EmulationEngineBuilder":
		self._post_emulation_routines.append(routine)
		return self

	def post_emulation_routines(self, routines: list[Callable]) -> "EmulationEngineBuilder":
		self._post_emulation_routines.extend(routines)
		return self

	def build(self) -> EmulationEngine:
		helper = BinaryViewHelper(self.bv)
		cls: EmulationEngine
		match helper.arch:
			case "arm":
				raise NotImplementedError
			case "aarch64":
				cls = Aarch64EmulationEngine

		chm = CodeHookManager(helper)
		for a, s in self.hooks:
			chm.register_hook(a, s)

		return cls(
			helper,
			chm,
			pre_emulation_routines=self._pre_emulation_routines,
			post_emulation_routines=self._post_emulation_routines,
		)
