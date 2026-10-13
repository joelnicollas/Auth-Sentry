#!/usr/bin/env python3

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from auth_sentry.parser import LogParser
from auth_sentry.engine import SIEMCorrelationEngine
from auth_sentry.reporter import ReportGenerator


def main():
    parser = argparse.ArgumentParser(
        description="AuthSentry: Detecção de ameaças e análise de logs de autenticação."
    )
    parser.add_argument("-f", "--file", required=True, help="Arquivo de log a ser analisado")
    parser.add_argument("--threshold", type=int, default=5, help="Limiar de falhas para alertar Brute Force (padrão: 5)")
    parser.add_argument("--json", help="Caminho para exportar relatório JSON")
    parser.add_argument("--md", help="Caminho para exportar relatório Markdown")

    args = parser.parse_args()

    log_path = Path(args.file)
    if not log_path.exists():
        print(f"[-] Erro: Arquivo de log '{args.file}' não foi encontrado.")
        sys.exit(1)

    events = []
    total_lines = 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            event = LogParser.parse_line(line)
            if event:
                events.append(event)

    engine = SIEMCorrelationEngine(brute_force_threshold=args.threshold)
    alerts = engine.analyze(events)

    ReportGenerator.print_terminal(total_lines, events, alerts)

    if args.json:
        ReportGenerator.export_json(alerts, args.json)
    if args.md:
        ReportGenerator.export_markdown(alerts, args.md)


if __name__ == "__main__":
    main()
