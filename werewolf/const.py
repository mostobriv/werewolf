import unicorn

from typing import Literal, LiteralString

Architecture = Literal["arm", "aarch64"]
Endianness = Literal["little", "big"]
Bitness = Literal[16, 32, 64]


def _inverted_dict(d: dict):
	return {v: k for (k, v) in d.items()}


WW_ENDIANNESS_LITTLE_ENDIAN: LiteralString = "little"
WW_ENDIANNESS_BIG_ENDIAN: LiteralString = "big"


endianness2uc: dict[LiteralString, int] = {
	WW_ENDIANNESS_LITTLE_ENDIAN: unicorn.unicorn_const.UC_MODE_LITTLE_ENDIAN,
	WW_ENDIANNESS_BIG_ENDIAN: unicorn.unicorn_const.UC_MODE_BIG_ENDIAN,
}
uc2endianness: dict[int, LiteralString] = _inverted_dict(endianness2uc)

WW_ARCH_ARM: LiteralString = "arm"
WW_ARCH_AARCH64: LiteralString = "aarch64"
WW_ARCH_X86: LiteralString = "x86"

arch2uc: dict[LiteralString, int] = {
	WW_ARCH_ARM: unicorn.unicorn_const.UC_ARCH_ARM,
	WW_ARCH_AARCH64: unicorn.unicorn_const.UC_ARCH_ARM64,
	WW_ARCH_X86: unicorn.unicorn_const.UC_ARCH_X86,
}
uc2arch: dict[int, LiteralString] = _inverted_dict(arch2uc)
