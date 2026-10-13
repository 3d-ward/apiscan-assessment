"""CSV renderers. Standard library only.

Three files rather than one: a findings register, the full test log, and the
coverage statement. Keeping them separate means each can be pivoted or diffed
without parsing a multi-table file.
"""
import csv
import os

from . import safe

#: Columns whose content the TARGET may have authored. Length-capped as well
#: as neutralised: a response body pasted whole makes the file unreadable.
UNTRUSTED_COLUMNS = frozenset([
    "description", "observed_behaviour", "notes", "reason", "conclusion",
    "impact", "expected_behaviour", "value",
])

FINDING_COLUMNS = [
    "id", "kind", "confidence", "severity", "title", "category", "cwe",
    "owasp", "affected", "endpoint_count", "occurrences", "cases",
    "provenance", "expected_behaviour", "observed_behaviour",
    "baseline_reference", "state_verification", "alternative_explanations",
    "limitations", "description", "impact", "recommendation", "conclusion",
    "notes",
]

LOG_COLUMNS = [
    "case_id", "phase", "family", "endpoint", "method", "payload_class",
    "expectation", "executed", "http_status", "layer", "verdict",
    "control_depth", "capture_method", "reason", "evidence", "description",
]


def _flatten(value):
    """Lists become one cell. A CSV has no nested structure to put them in."""
    if isinstance(value, (list, tuple)):
        return "; ".join(str(v) for v in value)
    return value


def _write(path, columns, rows):
    # safe.row neutralises spreadsheet formula injection: a target that
    # answers "=HYPERLINK(...)" in an error message would otherwise have that
    # formula evaluated in the client's spreadsheet, from the assessor's file.
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            flat = {k: _flatten(row.get(k, "")) for k in columns}
            w.writerow(safe.row(flat, columns, untrusted=UNTRUSTED_COLUMNS))
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
