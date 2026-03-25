"""Tests for SBOM profile parsing and framework detection."""

from src.sbom.profile import RepoProfile, parse_sbom, FRAMEWORK_INDICATORS, SECURITY_DEPS


FLASK_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {"type": "framework", "name": "Flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
        {"type": "library", "name": "gunicorn", "version": "21.2.0"},
        {"type": "library", "name": "requests", "version": "2.31.0"},
        {"type": "library", "name": "Jinja2", "version": "3.1.2"},
    ],
}

DJANGO_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {"type": "framework", "name": "Django", "version": "5.0.0"},
        {"type": "library", "name": "psycopg2", "version": "2.9.9"},
    ],
}

EXPRESS_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {"type": "library", "name": "express", "version": "4.18.2"},
        {"type": "library", "name": "helmet", "version": "7.1.0"},
        {"type": "library", "name": "csurf", "version": "1.11.0"},
    ],
}


def test_parse_flask_sbom():
    profile = parse_sbom(FLASK_SBOM)
    assert profile.framework == "flask"
    assert profile.language == "python"
    assert not profile.has_csrf_protection
    assert profile.has_xss_protection  # Jinja2 auto-escaping
    assert not profile.has_sql_orm


def test_parse_django_sbom():
    profile = parse_sbom(DJANGO_SBOM)
    assert profile.framework == "django"
    assert profile.has_csrf_protection
    assert profile.has_xss_protection
    assert profile.has_sql_orm


def test_parse_express_with_security_deps():
    profile = parse_sbom(EXPRESS_SBOM)
    assert profile.framework == "express"
    assert profile.language == "javascript"
    assert profile.has_csrf_protection  # csurf installed
    assert "helmet" in profile.security_deps
    assert "csurf" in profile.security_deps


def test_parse_empty_sbom():
    profile = parse_sbom({"components": []})
    assert profile.framework == ""
    assert profile.language == ""
    assert not profile.has_csrf_protection


def test_parse_none_sbom():
    profile = parse_sbom(None)
    assert profile.framework == ""
    assert profile.all_deps == []


SVELTE_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": [
        {"type": "library", "name": "@sveltejs/kit", "version": "2.0.0"},
        {"type": "library", "name": "svelte", "version": "5.0.0"},
    ],
}

NUXT_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": [
        {"type": "library", "name": "nuxt", "version": "3.10.0"},
        {"type": "library", "name": "vue", "version": "3.4.0"},
    ],
}

SPRING_SECURITY_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": [
        {"type": "library", "name": "spring-boot-starter-web", "version": "3.2.0"},
        {"type": "library", "name": "spring-security", "version": "6.2.0"},
    ],
}

RAILS_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": [{"type": "library", "name": "rails", "version": "7.1.0"}],
}

FASTAPI_ORM_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": [
        {"type": "library", "name": "fastapi", "version": "0.110.0"},
        {"type": "library", "name": "sqlalchemy", "version": "2.0.0"},
    ],
}

GIN_GORM_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": [
        {"type": "library", "name": "gin-gonic/gin", "version": "1.9.0"},
        {"type": "library", "name": "gorm", "version": "1.25.0"},
    ],
}

LARAVEL_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": [{"type": "library", "name": "laravel/framework", "version": "11.0.0"}],
}


def test_parse_svelte_sbom():
    profile = parse_sbom(SVELTE_SBOM)
    assert profile.framework == "sveltekit"
    assert profile.language == "javascript"


def test_parse_nuxt_sbom():
    profile = parse_sbom(NUXT_SBOM)
    assert profile.framework == "nuxt"
    assert profile.language == "javascript"


def test_parse_spring_security_sbom():
    profile = parse_sbom(SPRING_SECURITY_SBOM)
    assert profile.framework == "spring"
    assert profile.has_csrf_protection


def test_parse_rails_sbom():
    profile = parse_sbom(RAILS_SBOM)
    assert profile.framework == "rails"
    assert profile.has_csrf_protection
    assert profile.has_xss_protection
    assert profile.has_sql_orm


def test_parse_fastapi_with_orm():
    profile = parse_sbom(FASTAPI_ORM_SBOM)
    assert profile.framework == "fastapi"
    assert profile.has_sql_orm


def test_parse_gin_with_gorm():
    profile = parse_sbom(GIN_GORM_SBOM)
    assert profile.framework == "gin"
    assert profile.has_sql_orm


def test_parse_laravel_sbom():
    profile = parse_sbom(LARAVEL_SBOM)
    assert profile.framework == "laravel"
    assert profile.has_csrf_protection
