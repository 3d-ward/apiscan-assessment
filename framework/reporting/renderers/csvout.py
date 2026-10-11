"""CSV renderers. Standard library only.

Three files rather than one: a findings register, the full test log, and the
coverage statement. Keeping them separate means each can be pivoted or diffed
without parsing a multi-table file.
"""
import csv
import os

FINDING_COLUMNS = [
    "id", "kind", "severity", "title", "category", "cwe", "owasp",
    "affected", "endpoint_count", "occurrences", "cases", "provenance",
    "description", "impact", "recommendation", "conclusion", "notes",
]

LOG_COLUMNS = [
    "case_id", "phase", "family", "endpoint", "method", "payload_class",
    "expectation", "executed", "http_status", "layer", "verdict",
    "control_depth", "capture_method", "reason", "evidence", "description",
]


def _write(path, columns, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in columns})
    return path


def write(model, out_dir, prefix="report"):
    os.makedirs(out_dir, exist_ok=True)
    written = []
    written.append(_write(os.path.join(out_dir, "%s-findings.csv" % prefix),
                          FINDING_COLUMNS, model.findings_rows()))
    written.append(_write(os.path.join(out_dir, "%s-test-log.csv" % prefix),
                          LOG_COLUMNS, model.test_log_rows()))

    cov = model.coverage.statement()
    rows = [{"measure": k, "value": v} for k, v in cov["tally"].items()]
    rows += [{"measure": k, "value": v} for k, v in cov["percentages"].items()]
    rows.append({"measure": "status", "value": cov["status"]})
    rows.append({"measure": "baseline_ok", "value": cov["baseline"]["ok"]})
    for item in cov["not_established"]:
        rows.append({"measure": "not_established", "value": item})
    for item in cov["problems"]:
        rows.append({"measure": "problem", "value": item})
    written.append(_write(os.path.join(out_dir, "%s-coverage.csv" % prefix),
                          ["measure", "value"], rows))
    return written
