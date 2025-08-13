import binaryninja
from binaryninja import MediumLevelILOperation, HighLevelILOperation
from binaryninjaui import UIContext

from . import formalargument
from . import emu
from .emulengine.base import EmulationEngine
from .fileview.binaryninja import BinaryNinjaFileView


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

	fv = BinaryNinjaFileView(bv)
	formal_args = fv.get_formal_args_of_func(target_func_addr)
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
	return emu.run_emulate_function(fv, target_func_addr, concrete_args)


def run_emulate_hlil_call(
	instr: binaryninja.HighLevelILInstruction, bv: binaryninja.BinaryView | None = None
) -> EmulationEngine:
	if instr.operation != HighLevelILOperation.HLIL_CALL:
		raise ValueError(f"Expected HighLevelILLevelILCall, got {instr}")

	if bv is None:
		bv = _get_current_binary_view()

	target_func_addr = instr.dest.constant

	fv = BinaryNinjaFileView(bv)
	formal_args = fv.get_formal_args_of_func(target_func_addr)
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
	return emu.run_emulate_function(fv, target_func_addr, concrete_args)
