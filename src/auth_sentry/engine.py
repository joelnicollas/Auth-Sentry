from collections import defaultdict
from dataclasses import dataclass
from typing import List
from auth_sentry.parser import SecurityEvent


@dataclass
class Alert:
    rule_name: str
    severity: str
    source_ip: str
    target_users: List[str]
    count: int
    description: str
    evidence_timestamps: List[str]


class SIEMCorrelationEngine:
    def __init__(self, brute_force_threshold: int = 5, spraying_user_threshold: int = 3):
        self.brute_force_threshold = brute_force_threshold
        self.spraying_user_threshold = spraying_user_threshold

    def analyze(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []

        ip_failed_events = defaultdict(list)
        ip_success_events = defaultdict(list)
        ip_users_targeted = defaultdict(set)

        for ev in events:
            if ev.event_type in ("FAILED_LOGIN", "INVALID_USER"):
                ip_failed_events[ev.source_ip].append(ev)
                ip_users_targeted[ev.source_ip].add(ev.username)
            elif ev.event_type == "SUCCESS_LOGIN":
                ip_success_events[ev.source_ip].append(ev)

        for ip, failed_list in ip_failed_events.items():
            count = len(failed_list)
            target_users = list(ip_users_targeted[ip])
            timestamps = [e.timestamp for e in failed_list]

            if count >= self.brute_force_threshold and ip in ip_success_events:
                success_users = list({e.username for e in ip_success_events[ip]})
                alerts.append(
                    Alert(
                        rule_name="POSSIBLE_COMPROMISE_AFTER_BRUTEFORCE",
                        severity="CRITICAL",
                        source_ip=ip,
                        target_users=success_users,
                        count=count,
                        description=(
                            f"IP {ip} teve {count} falhas consecutivas e obteve "
                            f"sucesso de login nas contas: {success_users}."
                        ),
                        evidence_timestamps=timestamps[-5:],
                    )
                )

            elif count >= self.brute_force_threshold:
                alerts.append(
                    Alert(
                        rule_name="SSH_BRUTE_FORCE_ATTEMPT",
                        severity="HIGH",
                        source_ip=ip,
                        target_users=target_users,
                        count=count,
                        description=(
                            f"IP {ip} atingiu {count} tentativas com falha "
                            f"(limiar: {self.brute_force_threshold})."
                        ),
                        evidence_timestamps=timestamps[-5:],
                    )
                )

            users_count = len(ip_users_targeted[ip])
            if users_count >= self.spraying_user_threshold:
                alerts.append(
                    Alert(
                        rule_name="PASSWORD_SPRAYING_ATTACK",
                        severity="MEDIUM",
                        source_ip=ip,
                        target_users=target_users,
                        count=count,
                        description=(
                            f"IP {ip} atacou {users_count} contas distintas "
                            f"(alvos: {', '.join(target_users)})."
                        ),
                        evidence_timestamps=[e.timestamp for e in failed_list[-3:]],
                    )
                )

        return alerts
