import os
import sys
import subprocess
from pathlib import Path
from typing import Optional, Iterator


class SystemLogDetector:
    DEBIAN_AUTH_LOG = Path("/var/log/auth.log")

    @classmethod
    def get_log_stream(cls, user_provided_path: Optional[str]) -> Iterator[str]:
        if user_provided_path:
            p = Path(user_provided_path)
            if not p.exists():
                print(f"[-] Erro: Ficheiro especificado '{user_provided_path}' nao existe.")
                sys.exit(1)
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                yield from f
            return

        if cls.DEBIAN_AUTH_LOG.exists():
            if not os.access(cls.DEBIAN_AUTH_LOG, os.R_OK):
                print(f"[-] Permissao negada para ler '{cls.DEBIAN_AUTH_LOG}'. Execute com sudo.")
                sys.exit(1)
            with open(cls.DEBIAN_AUTH_LOG, "r", encoding="utf-8", errors="ignore") as f:
                yield from f
            return

        try:
            cmd = [
                "journalctl",
                "SYSLOG_FACILITY=4",
                "+",
                "SYSLOG_FACILITY=10",
                "--no-pager",
                "-o", "short"
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in proc.stdout:
                yield line
            proc.stdout.close()
            proc.wait()
        except FileNotFoundError:
            print("[-] Erro: Nem '/var/log/auth.log' nem 'journalctl' foram encontrados.")
            sys.exit(1)
