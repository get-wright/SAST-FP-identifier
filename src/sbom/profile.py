"""Parse CycloneDX SBOM into a RepoProfile for framework/security detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class RepoProfile:
    language: str = ""
    framework: str = ""
    all_deps: list[str] = field(default_factory=list)


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

def parse_sbom(sbom_json: Optional[dict[str, Any]]) -> RepoProfile:
    """Parse CycloneDX JSON into a RepoProfile.

    Extracts language, framework, and full dependency list from the SBOM.
    Framework detection uses FRAMEWORK_INDICATORS to map known package
    names to their framework/language. The LLM reasons about security
    capabilities from the raw dependency list — no hardcoded capability
    inference here.
    """
    if not sbom_json:
        return RepoProfile()

    components = sbom_json.get("components", [])
    if not components:
        return RepoProfile()

    all_deps = []
    framework = ""
    language = ""

    for comp in components:
        name = comp.get("name", "")
        name_lower = name.lower()
        all_deps.append(name)

        if name_lower in FRAMEWORK_INDICATORS:
            info = FRAMEWORK_INDICATORS[name_lower]
            if not framework:
                framework = info["framework"]
                language = info["language"]

    return RepoProfile(
        language=language,
        framework=framework,
        all_deps=all_deps,
    )
