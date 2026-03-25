"""Cross-reference SBOM dependencies against tree-sitter imports."""

from __future__ import annotations

from dataclasses import dataclass, field


# Common package-name → import-name mappings (Python-specific)
_PACKAGE_TO_IMPORT: dict[str, str] = {
    "pillow": "pil",
    "python-dateutil": "dateutil",
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn",
    "opencv-python": "cv2",
    "python-dotenv": "dotenv",
}


@dataclass
class ReachabilityMap:
    """Maps SBOM dependencies to where they're imported in the project."""

    dep_to_files: dict[str, list[str]] = field(default_factory=dict)
    file_to_deps: dict[str, list[str]] = field(default_factory=dict)
    all_sbom_deps: set[str] = field(default_factory=set)  # all normalized SBOM dep names


def build_reachability_map(
    file_imports: dict[str, list[str]],
    sbom_deps: list[str],
) -> ReachabilityMap:
    """Build a reachability map from file imports and SBOM dependency list.

    Args:
        file_imports: Map of file_path → list of import names (from tree-sitter).
        sbom_deps: List of package names from SBOM.
    """
    # Normalize SBOM dep names to lowercase import names
    dep_import_names: dict[str, str] = {}
    for dep in sbom_deps:
        dep_lower = dep.lower().replace("-", "_")
        import_name = _PACKAGE_TO_IMPORT.get(dep_lower, dep_lower)
        dep_import_names[dep_lower] = import_name

    rmap = ReachabilityMap(all_sbom_deps=set(dep_import_names.keys()))

    for file_path, imports in file_imports.items():
        imports_lower = {i.lower().split(".")[0] for i in imports}
        matched_deps = []

        for dep_name, import_name in dep_import_names.items():
            if import_name in imports_lower:
                matched_deps.append(dep_name)
                rmap.dep_to_files.setdefault(dep_name, []).append(file_path)

        rmap.file_to_deps[file_path] = matched_deps

    return rmap


def reachability_weight(
    finding_file: str,
    dep_name: str,
    rmap: ReachabilityMap,
) -> float:
    """Get the reachability weight for a finding's relevant dependency.

    Returns:
        1.0  — dep IS imported in this file (directly reachable)
        0.85 — dep imported elsewhere in project (indirectly reachable)
        0.60 — dep in SBOM but NOT imported anywhere
        1.0  — dep not in SBOM at all (neutral, no check possible)
    """
    dep_lower = dep_name.lower().replace("-", "_")
    import_name = _PACKAGE_TO_IMPORT.get(dep_lower, dep_lower)

    # Check if dep is in the SBOM at all
    if dep_lower not in rmap.all_sbom_deps:
        return 1.0  # neutral — not tracking this dep

    files_using = rmap.dep_to_files.get(dep_lower, [])

    if not files_using:
        return 0.60  # in SBOM but never imported

    if finding_file in files_using:
        return 1.0  # directly reachable

    return 0.85  # imported elsewhere
