"""Convert enrichment TaintFlow data into frontend flow_steps schema."""

from __future__ import annotations

from src.models.analysis import TaintFlow

_KIND_TO_LABEL = {
    "parameter": "source",
    "source": "source",
    "assignment": "propagation",
    "call_result": "propagation",
    "return": "propagation",
    "sink": "sink",
}


def ground_flow_steps(
    taint_flow: TaintFlow | None,
    file_path: str,
    joern_taint_path: list[str] | None = None,
) -> list[dict]:
    """Build frontend flow_steps from tree-sitter TaintFlow or Joern taint_path.

    Priority: tree-sitter TaintFlow > Joern taint_path > empty list.
    """
    if taint_flow is not None and taint_flow.path:
        return _from_taint_flow(taint_flow, file_path)
    if joern_taint_path:
        return _from_joern(joern_taint_path)
    return []


def _from_taint_flow(flow: TaintFlow, file_path: str) -> list[dict]:
    """Map tree-sitter TaintFlow to frontend steps, inject sanitizers and cross-file hops."""
    steps = [_flow_step_to_dict(s, file_path) for s in flow.path]
    steps = _inject_sanitizers(steps, flow.sanitizers, file_path)
    steps = _inject_cross_file_hops(steps, flow.cross_file_hops)
    return steps


def _flow_step_to_dict(step, file_path: str) -> dict:
    return {
        "label": _KIND_TO_LABEL.get(step.kind, "propagation"),
        "location": f"{file_path}:{step.line}",
        "code": step.expression,
        "explanation": "",
        "grounded": True,
    }


def _inject_sanitizers(steps: list[dict], sanitizers, file_path: str) -> list[dict]:
    if not sanitizers:
        return steps
    for san in sanitizers:
        entry = {
            "label": "sanitizer",
            "location": f"{file_path}:{san.line}",
            "code": san.name,
            "explanation": "",
            "grounded": True,
        }
        insert_idx = len(steps)
        for i, s in enumerate(steps):
            if _extract_line(s["location"]) > san.line:
                insert_idx = i
                break
        steps.insert(insert_idx, entry)
    return steps


def _inject_cross_file_hops(steps: list[dict], hops) -> list[dict]:
    if not hops:
        return steps
    # Collect cross-file entries to insert before the sink (last step).
    cross_entries: list[dict] = []
    for hop in hops:
        if hop.sub_flow and hop.sub_flow.path:
            for sub_step in hop.sub_flow.path:
                cross_entries.append(_flow_step_to_dict(sub_step, hop.file))
        else:
            cross_entries.append({
                "label": "propagation",
                "location": f"{hop.file}:{hop.line}",
                "code": f"{hop.callee}()",
                "explanation": "",
                "grounded": False,
            })
    # Insert before the last step (sink).
    if steps:
        sink = steps.pop()
        steps.extend(cross_entries)
        steps.append(sink)
    else:
        steps.extend(cross_entries)
    return steps


def _from_joern(joern_path: list[str]) -> list[dict]:
    """Parse Joern 'file:line:code' strings into flow steps."""
    results: list[dict] = []
    for i, entry in enumerate(joern_path):
        file_part, line_str, code = entry.split(":", 2)
        if i == 0:
            label = "source"
        elif i == len(joern_path) - 1 and len(joern_path) > 1:
            label = "sink"
        else:
            label = "propagation"
        results.append({
            "label": label,
            "location": f"{file_part}:{line_str}",
            "code": code,
            "explanation": "",
            "grounded": True,
        })
    return results


def _extract_line(location: str) -> int:
    """Extract line number from 'file:line' string."""
    return int(location.rsplit(":", 1)[1])
