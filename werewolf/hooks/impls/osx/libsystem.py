import os
import time

from ...hooks import function_hook


def getpid() -> int:
	return os.getpid()


def getppid() -> int:
	return os.getppid()


# def clock_gettime(clock_id: int, tp: int) -> int:
# def clock_gettime(context) -> int:
# 	try:
# 		time.clock_gettime(clock_id)
# 		return 0
# 	except os.OSError:
# 		return -1
