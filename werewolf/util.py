import struct


def p16(v: int) -> bytes:
	return struct.pack("H", v)


def p32(v: int) -> bytes:
	return struct.pack("I", v)


def p64(v: int) -> bytes:
	return struct.pack("Q", v)


def max_num_of_size(size: int) -> int:
	return (1 << size) - 1
