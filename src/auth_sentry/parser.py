import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityEvent:
    timestamp: str
    hostname: str
    process: str
    event_type: str
    username: str
    source_ip: str
    port: Optional[str]
    raw_message: str


class LogParser:
    PATTERNS = [
        (
            re.compile(
                r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>\S+)\s+(?P<proc>sshd\[\d+\]):\s+"
                r"Failed password for invalid user (?P<user>\S+)\s+"
                r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
            ),
            "INVALID_USER",
        ),
        (
            re.compile(
                r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>\S+)\s+(?P<proc>sshd\[\d+\]):\s+"
                r"Failed password for (?P<user>\S+)\s+"
                r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
            ),
            "FAILED_LOGIN",
        ),
        (
            re.compile(
                r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>\S+)\s+(?P<proc>sshd\[\d+\]):\s+"
                r"Accepted (?:password|publickey) for (?P<user>\S+)\s+"
                r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
            ),
            "SUCCESS_LOGIN",
        ),
        (
            re.compile(
                r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>\S+)\s+(?P<proc>sudo(?:\[\d+\])?):\s+"
                r"(?P<user>\S+)\s*:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target>\S+)\s+;\s+COMMAND=(?P<cmd>.*)"
            ),
            "SUDO_EXEC",
        ),
        (
            re.compile(
                r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>\S+)\s+(?P<proc>\S+\[\d+\]):\s+"
                r"pam_unix\(\S+\):\s+session opened for user (?P<user>\S+)"
            ),
            "SESSION_OPEN",
        ),
        (
            re.compile(
                r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>\S+)\s+(?P<proc>\S+\[\d+\]):\s+"
                r"pam_unix\(\S+\):\s+session closed for user (?P<user>\S+)"
            ),
            "SESSION_CLOSE",
        ),
    ]

    @classmethod
    def parse_line(cls, line: str) -> Optional[SecurityEvent]:
        sanitized_line = line.strip()
        if not sanitized_line:
            return None

        for pattern, event_type in cls.PATTERNS:
            match = pattern.search(sanitized_line)
            if match:
                data = match.groupdict()
                return SecurityEvent(
                    timestamp=data.get("time", ""),
                    hostname=data.get("host", ""),
                    process=data.get("proc", ""),
                    event_type=event_type,
                    username=data.get("user", "unknown"),
                    source_ip=data.get("ip", ""),
                    port=data.get("port"),
                    raw_message=sanitized_line,
                )
        return None
