"""Strict composition of the verified V1 API for a public prototype deployment."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI

from securemailscope.api import ApiSettings, create_app
from securemailscope.api.execution import BoundedAnalysisExecution
from securemailscope.errors import AnalysisError
from securemailscope.orchestration import OrchestrationDependencies
from securemailscope.tshark import run_tool

MINIMUM_TOOL_VERSION = (4, 2)


class DeploymentConfigurationError(ValueError):
    """Configuration failure containing field names only, never supplied values."""


class DeploymentReadinessError(RuntimeError):
    """Safe, actionable prerequisite failure."""


def _positive_integer(environment: Mapping[str, str], name: str, default: str) -> int:
    value = environment.get(name, default)
    if not re.fullmatch(r"[0-9]{1,10}", value):
        raise DeploymentConfigurationError(f"{name} must be a positive integer")
    parsed = int(value)
    if parsed < 1:
        raise DeploymentConfigurationError(f"{name} must be a positive integer")
    return parsed


def _origins(value: str, *, local_mode: bool) -> tuple[str, ...]:
    origins = []
    for entry in value.split(","):
        origin = entry.strip()
        try:
            parts = urlsplit(origin)
            host = parts.hostname
            port = parts.port
            is_local = host == "localhost" or bool(host and host.endswith(".localhost"))
            if host:
                try:
                    is_local = is_local or ipaddress.ip_address(host).is_loopback
                except ValueError:
                    pass  # A DNS hostname is checked below instead.
            if (
                not host
                or parts.scheme not in ({"https", "http"} if local_mode else {"https"})
                or (parts.scheme == "http" and not is_local)
                or (is_local and not local_mode)
                or parts.username is not None
                or parts.password is not None
                or parts.path
                or parts.query
                or parts.fragment
                or "?" in origin
                or "#" in origin
                or any(character.isspace() or ord(character) < 33 for character in origin)
                or "\\" in origin
                or "*" in origin
                or (port is not None and port < 1)
                or parts.netloc.endswith(":")
            ):
                raise ValueError
            # Restrict DNS labels or accept a syntactically valid IP literal.
            try:
                ipaddress.ip_address(host)
            except ValueError:
                labels = host.split(".")
                if (
                    len(host) > 253
                    or (not is_local and len(labels) < 2)
                    or re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", labels[-1])
                    or not all(
                        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                        for label in labels
                    )
                ):
                    raise ValueError from None
            if "%" in host:
                raise ValueError
            # Browser origins are canonical: lower-case host/scheme, no default port.
            authority = f"[{host}]" if ":" in host else host
            if port is not None and port != (443 if parts.scheme == "https" else 80):
                authority += f":{port}"
            normalized = f"{parts.scheme}://{authority}"
            if normalized not in origins:
                origins.append(normalized)
        except ValueError:
            raise DeploymentConfigurationError(
                "SECUREMAILSCOPE_ALLOWED_ORIGINS requires explicit valid HTTPS origins; "
                "loopback HTTP origins require explicit local_mode"
            ) from None
    return tuple(origins)


@dataclass(frozen=True)
class DeploymentSettings:
    """Validated environment boundary; use from_environment, not direct construction."""

    api: ApiSettings
    max_concurrent_analyses: int
    temporary_directory: Path
    port: int

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
        *,
        local_mode: bool = False,
    ) -> DeploymentSettings:
        env = os.environ if environment is None else environment
        origins = _origins(env.get("SECUREMAILSCOPE_ALLOWED_ORIGINS", ""), local_mode=local_mode)
        upload = _positive_integer(env, "SECUREMAILSCOPE_MAX_UPLOAD_BYTES", "1048576")
        entries = _positive_integer(env, "SECUREMAILSCOPE_MAX_REPOSITORY_ENTRIES", "16")
        concurrent = _positive_integer(env, "SECUREMAILSCOPE_MAX_CONCURRENT_ANALYSES", "1")
        port = _positive_integer(env, "PORT", "10000")
        if port > 65535:
            raise DeploymentConfigurationError("PORT must be between 1 and 65535")
        directory = Path(env.get("TMPDIR", "/tmp/securemailscope"))
        if not directory.is_absolute() or ".." in directory.parts or directory == Path("/"):
            raise DeploymentConfigurationError("TMPDIR must be an absolute private directory")
        return cls(
            api=ApiSettings(
                allowed_origins=origins,
                max_upload_bytes=upload,
                max_repository_entries=entries,
            ),
            max_concurrent_analyses=concurrent,
            temporary_directory=directory,
            port=port,
        )


def check_readiness(settings: DeploymentSettings) -> dict[str, str]:
    """Check offline tools and a private runtime-owned scratch directory before serving."""
    versions = {}
    for tool in ("tshark", "capinfos"):
        executable = shutil.which(tool)
        if executable is None or not os.access(executable, os.X_OK):
            raise DeploymentReadinessError(f"{tool} is unavailable or not executable")
        try:
            _, output = run_tool(
                [executable, "--version"],
                stage="deployment_readiness",
                timeout_seconds=5,
                max_output_chars=16384,
            )
        except (AnalysisError, OSError):
            raise DeploymentReadinessError(f"{tool} version check failed") from None
        version = re.match(
            r"(?:TShark|Capinfos) \(Wireshark\) (\d+)\.(\d+)\.(\d+)",
            output,
            re.IGNORECASE,
        )
        if version is None or tuple(map(int, version.groups()[:2])) < MINIMUM_TOOL_VERSION:
            raise DeploymentReadinessError(f"{tool} requires Wireshark 4.2 or newer")
        versions[tool] = ".".join(version.groups())

    directory = settings.temporary_directory
    try:
        # Do not follow a configured symlink or repair permissions on an existing directory.
        if any(part.is_symlink() for part in (directory, *directory.parents)):
            raise OSError
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.stat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise OSError
        with tempfile.TemporaryFile(dir=directory) as probe:
            probe.write(b"readiness")
            probe.flush()
    except OSError:
        raise DeploymentReadinessError(
            "TMPDIR must be a writable private directory owned by the runtime user"
        ) from None
    return versions


def create_deployment_app(
    settings: DeploymentSettings | None = None,
    *,
    orchestration_dependencies: OrchestrationDependencies | None = None,
) -> FastAPI:
    """Build an empty bounded V1 repository; never seed Live Analysis with fixture data."""
    configuration = settings or DeploymentSettings.from_environment()
    app = create_app(
        settings=configuration.api,
        orchestration_dependencies=orchestration_dependencies,
        analysis_execution=BoundedAnalysisExecution(configuration.max_concurrent_analyses),
        cors_allowed_headers=("Content-Type",),
    )
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        versions = await asyncio.to_thread(check_readiness, configuration)
        # Multipart spooling and server-named captures share this verified private directory.
        previous_directory = tempfile.tempdir
        tempfile.tempdir = str(configuration.temporary_directory)
        application.state.tool_versions = versions
        try:
            async with original_lifespan(application):
                yield
        finally:
            tempfile.tempdir = previous_directory

    app.router.lifespan_context = lifespan
    return app


def main() -> None:
    """Run as PID 1 without a shell; Uvicorn handles termination signals."""
    try:
        settings = DeploymentSettings.from_environment()
    except DeploymentConfigurationError as exc:
        raise SystemExit(str(exc)) from None
    uvicorn.run(
        create_deployment_app(settings),
        host="0.0.0.0",
        port=settings.port,
        workers=1,
        access_log=False,
    )


if __name__ == "__main__":
    main()
