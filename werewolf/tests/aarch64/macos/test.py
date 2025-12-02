from werewolf import bnscriptingprovider


def puts_hook(context):
	mem = context.memory_view
	s = mem.read_cstr(mem.read_reg(mem.regs.x0))

	assert s == b"HUYPIZDA"


def exit_hook(context):
	context.engine.stop_emulation()


builder = bnscriptingprovider.EmulationEngineBuilder()


engine = (
	builder.binary_view(bv)
	.code_hook(0x100000498, puts_hook)
	.code_hook(0x10000048C, exit_hook)
	.build()
)

engine.setup_stackframe(0x100000460)
engine.emulate_range(0x100000460, 0x100000484)
