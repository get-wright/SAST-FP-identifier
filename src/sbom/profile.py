"""Parse CycloneDX SBOM into a RepoProfile for framework/security detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class RepoProfile:
    language: str = ""
    framework: str = ""
    security_deps: list[str] = field(default_factory=list)
    all_deps: list[str] = field(default_factory=list)
    has_csrf_protection: bool = False
    has_xss_protection: bool = False
    has_sql_orm: bool = False


FRAMEWORK_INDICATORS: dict[str, dict[str, str]] = {
    # Python
    "flask": {"language": "python", "framework": "flask"},
    "django": {"language": "python", "framework": "django"},
    "fastapi": {"language": "python", "framework": "fastapi"},
    "tornado": {"language": "python", "framework": "tornado"},
    "bottle": {"language": "python", "framework": "bottle"},
    "pyramid": {"language": "python", "framework": "pyramid"},
    "sanic": {"language": "python", "framework": "sanic"},
    "starlette": {"language": "python", "framework": "starlette"},
    "aiohttp": {"language": "python", "framework": "aiohttp"},
    "falcon": {"language": "python", "framework": "falcon"},
    "litestar": {"language": "python", "framework": "litestar"},
    "quart": {"language": "python", "framework": "quart"},
    # JavaScript / TypeScript
    "express": {"language": "javascript", "framework": "express"},
    "next": {"language": "javascript", "framework": "next"},
    "koa": {"language": "javascript", "framework": "koa"},
    "hono": {"language": "javascript", "framework": "hono"},
    "fastify": {"language": "javascript", "framework": "fastify"},
    "nest": {"language": "javascript", "framework": "nest"},
    "@nestjs/core": {"language": "javascript", "framework": "nest"},
    "nuxt": {"language": "javascript", "framework": "nuxt"},
    "svelte": {"language": "javascript", "framework": "svelte"},
    "@sveltejs/kit": {"language": "javascript", "framework": "sveltekit"},
    "remix": {"language": "javascript", "framework": "remix"},
    "@remix-run/node": {"language": "javascript", "framework": "remix"},
    "gatsby": {"language": "javascript", "framework": "gatsby"},
    "astro": {"language": "javascript", "framework": "astro"},
    "solid-js": {"language": "javascript", "framework": "solid"},
    "elysia": {"language": "javascript", "framework": "elysia"},
    "adonis": {"language": "javascript", "framework": "adonis"},
    "@adonisjs/core": {"language": "javascript", "framework": "adonis"},
    # PHP
    "laravel/framework": {"language": "php", "framework": "laravel"},
    "symfony/framework-bundle": {"language": "php", "framework": "symfony"},
    "slim/slim": {"language": "php", "framework": "slim"},
    "cakephp/cakephp": {"language": "php", "framework": "cakephp"},
    "yiisoft/yii2": {"language": "php", "framework": "yii"},
    "codeigniter4/framework": {"language": "php", "framework": "codeigniter"},
    # Java / Kotlin
    "spring-boot": {"language": "java", "framework": "spring"},
    "spring-boot-starter-web": {"language": "java", "framework": "spring"},
    "spring-webflux": {"language": "java", "framework": "spring"},
    "micronaut": {"language": "java", "framework": "micronaut"},
    "quarkus": {"language": "java", "framework": "quarkus"},
    "ktor": {"language": "kotlin", "framework": "ktor"},
    "dropwizard": {"language": "java", "framework": "dropwizard"},
    "vertx": {"language": "java", "framework": "vertx"},
    # Ruby
    "rails": {"language": "ruby", "framework": "rails"},
    "sinatra": {"language": "ruby", "framework": "sinatra"},
    "hanami": {"language": "ruby", "framework": "hanami"},
    "grape": {"language": "ruby", "framework": "grape"},
    "padrino": {"language": "ruby", "framework": "padrino"},
    # Go
    "gin-gonic/gin": {"language": "go", "framework": "gin"},
    "labstack/echo": {"language": "go", "framework": "echo"},
    "gofiber/fiber": {"language": "go", "framework": "fiber"},
    "gorilla/mux": {"language": "go", "framework": "gorilla"},
    "go-chi/chi": {"language": "go", "framework": "chi"},
    "beego": {"language": "go", "framework": "beego"},
    # Rust
    "actix-web": {"language": "rust", "framework": "actix"},
    "rocket": {"language": "rust", "framework": "rocket"},
    "axum": {"language": "rust", "framework": "axum"},
    "warp": {"language": "rust", "framework": "warp"},
    "tide": {"language": "rust", "framework": "tide"},
    # C#
    "microsoft.aspnetcore.app": {"language": "csharp", "framework": "aspnet"},
    "microsoft.aspnetcore": {"language": "csharp", "framework": "aspnet"},
    # Elixir
    "phoenix": {"language": "elixir", "framework": "phoenix"},
    "plug": {"language": "elixir", "framework": "plug"},
    # Scala
    "play": {"language": "scala", "framework": "play"},
    "akka-http": {"language": "scala", "framework": "akka-http"},
    "com.typesafe.play": {"language": "scala", "framework": "play"},
    "com.typesafe.akka": {"language": "scala", "framework": "akka-http"},
    # Swift
    "vapor": {"language": "swift", "framework": "vapor"},
}

SECURITY_DEPS: dict[str, dict[str, list[str]]] = {
    # Python
    "flask-wtf": {"provides": ["csrf"]},
    "django": {"provides": ["csrf", "xss", "orm"]},
    "jinja2": {"provides": ["xss"]},
    "markupsafe": {"provides": ["xss"]},
    "python-jose": {"provides": ["auth"]},
    "pyjwt": {"provides": ["auth"]},
    "bcrypt": {"provides": ["auth"]},
    "passlib": {"provides": ["auth"]},
    "sqlalchemy": {"provides": ["orm"]},
    "tortoise-orm": {"provides": ["orm"]},
    "peewee": {"provides": ["orm"]},
    "bleach": {"provides": ["xss_sanitizer"]},
    # JavaScript
    "csurf": {"provides": ["csrf"]},
    "csrf": {"provides": ["csrf"]},
    "csrf-csrf": {"provides": ["csrf"]},
    "lusca": {"provides": ["csrf"]},
    "helmet": {"provides": ["xss_headers"]},
    "dompurify": {"provides": ["xss_sanitizer"]},
    "sanitize-html": {"provides": ["xss_sanitizer"]},
    "xss": {"provides": ["xss_sanitizer"]},
    "sequelize": {"provides": ["orm"]},
    "prisma": {"provides": ["orm"]},
    "@prisma/client": {"provides": ["orm"]},
    "typeorm": {"provides": ["orm"]},
    "drizzle-orm": {"provides": ["orm"]},
    "knex": {"provides": ["orm"]},
    "mongoose": {"provides": ["orm"]},
    "jsonwebtoken": {"provides": ["auth"]},
    "passport": {"provides": ["auth"]},
    "bcryptjs": {"provides": ["auth"]},
    "argon2": {"provides": ["auth"]},
    # PHP
    "paragonie/anti-csrf": {"provides": ["csrf"]},
    "doctrine/orm": {"provides": ["orm"]},
    "doctrine/dbal": {"provides": ["orm"]},
    "illuminate/database": {"provides": ["orm"]},
    # Java
    "spring-security": {"provides": ["csrf", "xss"]},
    "spring-security-web": {"provides": ["csrf", "xss"]},
    "hibernate": {"provides": ["orm"]},
    "mybatis": {"provides": ["orm"]},
    # Ruby
    "activerecord": {"provides": ["orm"]},
    "rack-csrf": {"provides": ["csrf"]},
    "rack_csrf": {"provides": ["csrf"]},
    "sanitize": {"provides": ["xss_sanitizer"]},
    # Go
    "gorilla/csrf": {"provides": ["csrf"]},
    "gorm": {"provides": ["orm"]},
    "sqlx": {"provides": ["orm"]},
    "ent": {"provides": ["orm"]},
    # Rust
    "diesel": {"provides": ["orm"]},
    "sea-orm": {"provides": ["orm"]},
    # Elixir
    "ecto": {"provides": ["orm"]},
    # C#
    "entity-framework": {"provides": ["orm"]},
    "microsoft.entityframeworkcore": {"provides": ["orm"]},
}

# Framework-implied protections (even without explicit security deps)
_FRAMEWORK_PROTECTIONS: dict[str, dict[str, bool]] = {
    "django": {"csrf": True, "xss": True, "orm": True},
    "rails": {"csrf": True, "xss": True, "orm": True},
    "laravel": {"csrf": True, "xss": True, "orm": True},
    "flask": {"xss": True},  # Jinja2 auto-escaping, but NO csrf
    "spring": {},  # needs spring-security for csrf
    "express": {},  # needs csurf/helmet explicitly
    # JS frameworks with auto-escaping (XSS protection)
    "next": {"xss": True},
    "nuxt": {"xss": True},
    "svelte": {"xss": True},
    "sveltekit": {"xss": True},
    "remix": {"xss": True},
    "gatsby": {"xss": True},
    "solid": {"xss": True},
    # PHP frameworks with built-in CSRF
    "cakephp": {"csrf": True},
    "yii": {"csrf": True},
    "codeigniter": {"csrf": True},
    # Ruby
    "hanami": {"csrf": True},
    # C#
    "aspnet": {"csrf": True, "xss": True},
    # Elixir
    "phoenix": {"csrf": True, "xss": True},
    # Rust
    "rocket": {"csrf": True},
    # JS
    "adonis": {"csrf": True},
}


def parse_sbom(sbom_json: Optional[dict[str, Any]]) -> RepoProfile:
    """Parse CycloneDX JSON into a RepoProfile."""
    if not sbom_json:
        return RepoProfile()

    components = sbom_json.get("components", [])
    if not components:
        return RepoProfile()

    all_deps = []
    framework = ""
    language = ""
    found_protections: set[str] = set()
    security_deps: list[str] = []

    for comp in components:
        name = comp.get("name", "")
        name_lower = name.lower()
        all_deps.append(name)

        # Detect framework
        if name_lower in FRAMEWORK_INDICATORS:
            info = FRAMEWORK_INDICATORS[name_lower]
            if not framework:  # first match wins
                framework = info["framework"]
                language = info["language"]

        # Detect security deps
        if name_lower in SECURITY_DEPS:
            security_deps.append(name_lower)
            for prov in SECURITY_DEPS[name_lower]["provides"]:
                found_protections.add(prov)

    # Apply framework-implied protections
    if framework in _FRAMEWORK_PROTECTIONS:
        for prot, enabled in _FRAMEWORK_PROTECTIONS[framework].items():
            if enabled:
                found_protections.add(prot)

    return RepoProfile(
        language=language,
        framework=framework,
        security_deps=security_deps,
        all_deps=all_deps,
        has_csrf_protection="csrf" in found_protections,
        has_xss_protection="xss" in found_protections or "xss_headers" in found_protections or "xss_sanitizer" in found_protections,
        has_sql_orm="orm" in found_protections,
    )
