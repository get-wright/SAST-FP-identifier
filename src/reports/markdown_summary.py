"""Build Markdown summary report from analysis results."""

from __future__ import annotations

from src.models.analysis import AnalysisResult


def build_markdown_summary(result: AnalysisResult, threshold: float = 0.8) -> str:
    """Build human-readable Markdown report."""
    true_pos = []
    false_pos = []
    uncertain = []

    for fg in result.file_groups:
        for v in fg.verdicts:
            cls = v.classification(threshold)
            entry = (fg.file_path, v)
            if cls == "true_positive":
                true_pos.append(entry)
            elif cls == "false_positive":
                false_pos.append(entry)
            else:
                uncertain.append(entry)

    total = len(true_pos) + len(false_pos) + len(uncertain)

    lines = [
        "# Semgrep False-Positive Analysis Report",
        f"Repository: {result.repo_url}",
        f"Commit: {result.commit_sha}",
        f"Findings: {total} total -> {len(true_pos)} true positives, "
        f"{len(false_pos)} false positives, {len(uncertain)} uncertain",
        "",
    ]

    if result.warnings:
        for w in result.warnings:
            lines.append(f"> WARNING: {w}")
        lines.append("")

    # True positives
    lines.append(f"## True Positives ({len(true_pos)}) -- Action Required")
    if true_pos:
        lines.append("| File | Line | Confidence | Reasoning | Remediation |")
        lines.append("|------|------|------------|-----------|-------------|")
        for file_path, v in sorted(true_pos, key=lambda x: -x[1].confidence):
            rem = (v.remediation_explanation or "--")[:60]
            lines.append(
                f"| {file_path} | {v.finding_index} | {v.confidence:.0%} | "
                f"{v.reasoning[:60]} | {rem} |"
            )
    else:
        lines.append("None.")
    lines.append("")

    # Dataflow details for true positives
    df_entries = [(fp, v) for fp, v in true_pos
                  if v.dataflow_analysis and not v.dataflow_analysis.startswith("Not applicable")]
    if df_entries:
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Dataflow Details</summary>")
        lines.append("")
        for file_path, v in df_entries:
            lines.append(f"**{file_path}:{v.finding_index}** — {v.dataflow_analysis}")
            lines.append("")
        lines.append("</details>")

    # False positives
    lines.append(f"## False Positives ({len(false_pos)}) -- Can Dismiss")
    if false_pos:
        lines.append("| File | Line | Confidence | Reasoning |")
        lines.append("|------|------|------------|-----------|")
        for file_path, v in sorted(false_pos, key=lambda x: -x[1].confidence):
            lines.append(
                f"| {file_path} | {v.finding_index} | {v.confidence:.0%} | "
                f"{v.reasoning[:80]} |"
            )
    else:
        lines.append("None.")
    lines.append("")

    # Dataflow details for false positives
    df_entries = [(fp, v) for fp, v in false_pos
                  if v.dataflow_analysis and not v.dataflow_analysis.startswith("Not applicable")]
    if df_entries:
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Dataflow Details</summary>")
        lines.append("")
        for file_path, v in df_entries:
            lines.append(f"**{file_path}:{v.finding_index}** — {v.dataflow_analysis}")
            lines.append("")
        lines.append("</details>")

    # Uncertain
    lines.append(f"## Uncertain ({len(uncertain)}) -- Needs Manual Review")
    if uncertain:
        lines.append("| File | Line | Confidence | Reasoning |")
        lines.append("|------|------|------------|-----------|")
        for file_path, v in sorted(uncertain, key=lambda x: -x[1].confidence):
            lines.append(
                f"| {file_path} | {v.finding_index} | {v.confidence:.0%} | "
                f"{v.reasoning[:80]} |"
            )
    else:
        lines.append("None.")

    # Dataflow details for uncertain
    df_entries = [(fp, v) for fp, v in uncertain
                  if v.dataflow_analysis and not v.dataflow_analysis.startswith("Not applicable")]
    if df_entries:
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Dataflow Details</summary>")
        lines.append("")
        for file_path, v in df_entries:
            lines.append(f"**{file_path}:{v.finding_index}** — {v.dataflow_analysis}")
            lines.append("")
        lines.append("</details>")

    return "\n".join(lines)
