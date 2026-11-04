#!/usr/bin/env python3

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from auth_sentry.parser import LogParser
from auth_sentry.engine import SIEMCorrelationEngine
from auth_sentry.reporter import ReportGenerator
from auth_sentry.detector import SystemLogDetector


def main():
    parser = argparse.ArgumentParser(
        description="AuthSentry: Detecao de ameacas e correlacao de logs de autenticacao."
    )
    parser.add_argument(
        "-f",
        "--file",
        required=False,
        default=None,
        help="Caminho do ficheiro de log"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Limiar de falhas para disparar alerta de Brute Force"
    )
    parser.add_argument("--json", help="Caminho para exportar relatorio JSON")
    parser.add_argument("--md", help="Caminho para exportar relatorio Markdown")

    args = parser.parse_args()

    events = []
    total_lines = 0

    for line in SystemLogDetector.get_log_stream(args.file):
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
