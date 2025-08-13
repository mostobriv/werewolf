from werewolf.fileview.base import FileView
from werewolf.memory import MemoryView

from enum import IntEnum


class ApplyOptions(IntEnum):
	ApplyAll = 0
	ApplyIfNullOnly = 1


class MemoryDiffer:
	def __init__(self, runtime_memory: MemoryView, file_memory: FileView):
		self.runtime = runtime_memory
		self.static = file_memory

	def changed_data(self):
		runtime_regions = self.runtime.memory_regions()
		for start, end, _ in runtime_regions:
			if not self.static.address_is_filebacked(start):
				continue

			first = self.runtime.read_bytes(start, end - start + 1)
			second = self.static.read_bytes(start, end - start + 1)
			if not self.compare_blobs(first, second):
				yield (start, end)

	def compare_blobs(self, first: bytes, second: bytes) -> bool:
		return first == second

	def apply_changes(
		self, options: ApplyOptions = ApplyOptions.ApplyIfNullOnly, granularity: int = 8
	):
		for start, end in self.changed_data():
			new = self.runtime.read_bytes(start, end - start + 1)
			old = self.static.read_bytes(start, end - start + 1)
			for i in range(len(new)):
				if old[i] != new[i]:
					self.static.write_bytes(start + i, new[i].to_bytes())
