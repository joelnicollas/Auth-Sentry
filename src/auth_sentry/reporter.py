import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from auth_sentry.engine import Alert
from auth_sentry.parser import SecurityEvent


class ReportGenerator:
    @staticmethod
    def print_terminal(total_lines: int, events: List[SecurityEvent], alerts: List[Alert]) -> None:
        print("\n" + "=" * 70)
        print("          AUTHSENTRY - RELATÓRIO DE MONITORAMENTO SOC          ")
        print("=" * 70)
        print(f"[*] Linhas de log analisadas : {total_lines}")
        print(f"[*] Eventos estruturados     : {len(events)}")
        print(f"[*] Alertas de segurança     : {len(alerts)}")
        print("-" * 70)

        if not alerts:
            print("[+] Nenhuma anomalia detectada acima dos limiares de segurança.")
            print("=" * 70 + "\n")
            return

        for alert in alerts:
            print(f"\n[{alert.severity}] Regra: {alert.rule_name}")
            print(f"  Origem : {alert.source_ip}")
            print(f"  Alvos  : {', '.join(alert.target_users)}")
            print(f"  Resumo : {alert.description}")
            print(f"  Evidências: {', '.join(alert.evidence_timestamps)}")

        print("\n" + "=" * 70 + "\n")

    @staticmethod
    def export_json(alerts: List[Alert], output_path: str) -> None:
        data = [asdict(a) for a in alerts]
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with open(destination, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "total_alerts": len(alerts),
                    "alerts": data,
                },
                f,
                indent=2,
            )
        print(f"[+] Relatório JSON exportado para: {destination.resolve()}")

    @staticmethod
    def export_markdown(alerts: List[Alert], output_path: str) -> None:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with open(destination, "w", encoding="utf-8") as f:
            f.write("# Relatório de Incidentes de Segurança - AuthSentry\n\n")
            f.write(f"**Data da Execução:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  \n")
            f.write(f"**Total de Alertas:** {len(alerts)}\n\n")
            f.write("| Severidade | Regra Disparada | IP Origem | Usuários Alvo | Detalhes |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- |\n")
            for a in alerts:
                users = "<br>".join(a.target_users)
                f.write(f"| **{a.severity}** | `{a.rule_name}` | `{a.source_ip}` | {users} | {a.description} |\n")
        print(f"[+] Relatório Markdown exportado para: {destination.resolve()}")
