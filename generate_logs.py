from pathlib import Path

SAMPLE_LOG_DATA = """Oct 13 01:10:02 debian-server sshd[2041]: Accepted password for joel from 192.168.1.15 port 52120 ssh2
Oct 13 01:12:10 debian-server sshd[2055]: Failed password for invalid user admin from 203.0.113.45 port 39401 ssh2
Oct 13 01:12:12 debian-server sshd[2056]: Failed password for invalid user test from 203.0.113.45 port 39402 ssh2
Oct 13 01:12:15 debian-server sshd[2057]: Failed password for root from 203.0.113.45 port 39403 ssh2
Oct 13 01:12:18 debian-server sshd[2058]: Failed password for invalid user guest from 203.0.113.45 port 39404 ssh2
Oct 13 01:15:20 debian-server sshd[2101]: Failed password for root from 198.51.100.88 port 48101 ssh2
Oct 13 01:15:21 debian-server sshd[2102]: Failed password for root from 198.51.100.88 port 48102 ssh2
Oct 13 01:15:23 debian-server sshd[2103]: Failed password for root from 198.51.100.88 port 48103 ssh2
Oct 13 01:15:25 debian-server sshd[2104]: Failed password for root from 198.51.100.88 port 48104 ssh2
Oct 13 01:15:26 debian-server sshd[2105]: Failed password for root from 198.51.100.88 port 48105 ssh2
Oct 13 01:15:28 debian-server sshd[2106]: Failed password for root from 198.51.100.88 port 48106 ssh2
Oct 13 01:16:00 debian-server sshd[2150]: Failed password for ubuntu from 192.0.2.77 port 55101 ssh2
Oct 13 01:16:02 debian-server sshd[2151]: Failed password for ubuntu from 192.0.2.77 port 55102 ssh2
Oct 13 01:16:04 debian-server sshd[2152]: Failed password for ubuntu from 192.0.2.77 port 55103 ssh2
Oct 13 01:16:05 debian-server sshd[2153]: Failed password for ubuntu from 192.0.2.77 port 55104 ssh2
Oct 13 01:16:07 debian-server sshd[2154]: Failed password for ubuntu from 192.0.2.77 port 55105 ssh2
Oct 13 01:16:12 debian-server sshd[2155]: Accepted password for ubuntu from 192.0.2.77 port 55106 ssh2
"""

def generate_sample_logs(target_file: str = "data/auth_sample.log") -> None:
    destination = Path(target_file)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", encoding="utf-8") as f:
        f.write(SAMPLE_LOG_DATA.strip() + "\n")
    print(f"[+] Amostra de logs gerada em: {destination.resolve()}")

if __name__ == "__main__":
    generate_sample_logs()
