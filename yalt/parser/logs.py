# yalt/parser/logs.py

from dataclasses import dataclass
from typing import Optional


@dataclass
class LogEntry:
	action: Optional[str]
	interface: Optional[str]
	protocol: Optional[str]
	src_ip: Optional[str]
	dst_ip: Optional[str]
	src_port: Optional[int]
	dst_port: Optional[int]
	raw: str  # keep full line for debugging


def _safe_int(value: Optional[str]) -> Optional[int]:
	if not value:
		return None
	try:
		return int(value)
	except ValueError:
		return None


def parse_filterlog_line(line: str) -> Optional[LogEntry]:
	line = line.strip()

	# Skip empty or unrelated lines
	if "filterlog[" not in line and "filterlog:" not in line:
		return None

	raw = line

	# Split at the FIRST colon AFTER "filterlog[...]"
	try:
		prefix, rest = line.split("]:", 1)
		csv_part = rest.strip()
	except ValueError:
		# fallback for rare "filterlog:" format
		try:
			_, csv_part = line.split("filterlog:", 1)
			csv_part = csv_part.strip()
		except ValueError:
			return None

	fields = [f.strip() for f in csv_part.split(",")]

	# Your pfSense format uses at least 22 fields
	if len(fields) < 22:
		return None

	try:
		interface = fields[4]
		action = fields[6]
		protocol = fields[16]
		src_ip = fields[18]
		dst_ip = fields[19]
		src_port = _safe_int(fields[20])
		dst_port = _safe_int(fields[21])
	except Exception:
		return None

	return LogEntry(
		action=action,
		interface=interface,
		protocol=protocol,
		src_ip=src_ip,
		dst_ip=dst_ip,
		src_port=src_port,
		dst_port=dst_port,
		raw=raw,
	)



def parse_log_file(path: str):
	entries = []
	with open(path, "r", encoding="utf-8", errors="ignore") as f:
		for line in f:
			entry = parse_filterlog_line(line)
			if entry is not None:
				entries.append(entry)
	return entries
