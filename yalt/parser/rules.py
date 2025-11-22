# yalt/parser/rules.py


import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional, List


@dataclass

class PFRule:
	action: str
	interface: Optional[str]
	protocol: Optional[str]
	src_ip: Optional[str]
	src_port: Optional[str]
	dst_ip: Optional[str]
	dst_port: Optional[str]
	nat_target_ip: Optional[str]
	nat_target_port: Optional[str]
	description: Optional[str]


def parse_pfsense_rules(path: str) -> List[PFRule]:
	tree = ET.parse(path)
	root = tree.getroot()

	rules: List[PFRule] = []

	filter_section = root.find("filter")
	if filter_section is None:
		return rules

	for elem in filter_section.findall("rule"):

		# basic fields
		action = elem.findtext("type") or "pass"
		interface = elem.findtext("interface")
		protocol = elem.findtext("protocol")
		description = elem.findtext("descr")

		# source
		src_elem = elem.find("source")
		src_ip = None
		src_port = None

		if src_elem is not None:
			# <any></any> → treat as None
			if src_elem.find("any") is None:
				src_ip = src_elem.findtext("address")
				src_port = src_elem.findtext("port")

		# destination (WAN side)
		dst_elem = elem.find("destination")
		dst_ip = None
		dst_port = None

		if dst_elem is not None:
			dst_ip = dst_elem.findtext("address") or dst_elem.findtext("network")
			dst_port = dst_elem.findtext("port")

		# NAT target (LAN side)
		nat_target_ip = elem.findtext("target")
		nat_target_port = elem.findtext("local-port")

		rule = PFRule(
			action=action,
			interface=interface,
			protocol=protocol,
			src_ip=src_ip,
			src_port=src_port,
			dst_ip=dst_ip,
			dst_port=dst_port,
			nat_target_ip=nat_target_ip,
			nat_target_port=nat_target_port,
			description=description
		)

		rules.append(rule)

	return rules
