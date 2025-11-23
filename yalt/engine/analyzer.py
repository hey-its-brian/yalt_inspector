

from dataclasses import dataclass
from typing import List, Optional, Literal

from yalt.parser.rules import PFRule
from yalt.parser.logs import LogEntry

AnomalyType = Literal["no_matching_rule", "action_mismatch"]

@dataclass
class Anomaly:
    kind: AnomalyType
    log: LogEntry
    matching_rules: List[PFRule]
    reason: str

def _match_field(rule_value: Optional[str], log_value: Optional[str]) -> bool:
    #if rule_value is None -> treat as "any"
    if rule_value is None:
        return True

    # if the log value is missing, no match
    if log_value is None:
        return False

    # otherwise require exact equality (v0 is simple)
    return rule_value == log_value

def _rule_matches_log(rule: PFRule, log: LogEntry) -> bool:
    # interface
    if not _match_field(rule.interface, log.interface):
        return False

    # protocol
    if not _match_field(rule.protocol, log.protocol):
        return False

    # source ip
    if rule.src_ip and rule.src_ip != log.src_ip:
        return False

    #destination ip
    if rule.dst_ip and rule.dst_ip != log.dst_ip:
        return False

    # source port
    if rule.src_port and log.src_port is not None:
        if rule.src_port != str(log.src_port):
            if rule.dst_port != str(log.dst_port):
                return False

    return True

def analyze_logs(rules: List[PFRule], logs: List[LogEntry]) -> List[Anomaly]:
    anomalies: List[Anomaly] = []

    for log in logs:
        matching = [r for r in rules if _rule_matches_log(r,log)]

        # no matching rule at all
        if not matching:
            anomalies.append(
                Anomaly(
                    kind="no_matching_rule",
                    log=log,
                    matching_rules=[],
                    reason="No firewall rule matched this log entry."
                )
            )
            continue

        # if every matching rule says one action but log says another
        rule_actions = {r.action for r in matching if r.action}
        log_action = log.action or ""

        if rule_actions and all(a != log_action for a in rule_actions):
            anomalies.append(
                Anomaly(
                    kind="action_mismatch",
                    log=log,
                    matching_rules=matching,

                )
            )

