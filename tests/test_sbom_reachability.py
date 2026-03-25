"""Tests for import reachability cross-referencing."""

from src.sbom.reachability import ReachabilityMap, build_reachability_map, reachability_weight

MOCK_FILE_IMPORTS = {
    "app/sw.py": ["flask", "requests", "hashlib", "json", "os"],
    "app/api.py": ["flask", "sqlalchemy"],
    "extension/sidepanel.js": [],
}

SBOM_DEPS = ["Flask", "requests", "gunicorn", "APScheduler", "SQLAlchemy"]


def test_build_reachability_map():
    rmap = build_reachability_map(MOCK_FILE_IMPORTS, SBOM_DEPS)
    assert "app/sw.py" in rmap.dep_to_files.get("flask", [])
    assert "flask" in rmap.file_to_deps.get("app/sw.py", [])


def test_reachability_weight_dep_in_file():
    rmap = build_reachability_map(MOCK_FILE_IMPORTS, SBOM_DEPS)
    # requests is imported in app/sw.py
    w = reachability_weight("app/sw.py", "requests", rmap)
    assert w == 1.0


def test_reachability_weight_dep_in_project_not_file():
    rmap = build_reachability_map(MOCK_FILE_IMPORTS, SBOM_DEPS)
    # sqlalchemy is imported in app/api.py but not app/sw.py
    w = reachability_weight("app/sw.py", "sqlalchemy", rmap)
    assert w == 0.85


def test_reachability_weight_dep_not_imported():
    rmap = build_reachability_map(MOCK_FILE_IMPORTS, SBOM_DEPS)
    # gunicorn is in SBOM but not imported anywhere
    w = reachability_weight("app/sw.py", "gunicorn", rmap)
    assert w == 0.60


def test_reachability_weight_no_relevant_dep():
    rmap = build_reachability_map(MOCK_FILE_IMPORTS, SBOM_DEPS)
    # nonexistent dep
    w = reachability_weight("app/sw.py", "nonexistent", rmap)
    assert w == 1.0  # neutral — no dep to check against
