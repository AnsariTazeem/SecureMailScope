"""Offline checks for the strict deployment boundary and startup prerequisites."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

import securemailscope.deployment as deployment
from securemailscope.api import ApiSettings
from securemailscope.deployment import (
    DeploymentConfigurationError,
    DeploymentReadinessError,
    DeploymentSettings,
    check_readiness,
    create_deployment_app,
)

ORIGIN = "https://secure-mail-scope.vercel.app"


def configuration(tmp_path: Path, **values: str) -> DeploymentSettings:
    return DeploymentSettings.from_environment(
        {"SECUREMAILSCOPE_ALLOWED_ORIGINS": ORIGIN, "TMPDIR": str(tmp_path / "private"), **values}
    )


def fake_tools(monkeypatch: pytest.MonkeyPatch, *, version: str = "4.2.2") -> list[list[str]]:
    calls = []
    monkeypatch.setattr(deployment.shutil, "which", lambda tool: f"/tools/{tool}")
    monkeypatch.setattr(deployment.os, "access", lambda *args: True)

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs == {
            "stage": "deployment_readiness",
            "timeout_seconds": 5,
            "max_output_chars": 16384,
        }
        name = "TShark" if argv[0].endswith("tshark") else "Capinfos"
        return None, f"{name} (Wireshark) {version} (packaged build)\n"

    monkeypatch.setattr(deployment, "run_tool", run)
    return calls


def test_deployment_defaults_are_small_and_factory_defaults_remain_unchanged(tmp_path):
    settings = configuration(tmp_path)
    assert settings.api.allowed_origins == (ORIGIN,)
    assert settings.api.max_upload_bytes == 1048576
    assert settings.api.max_repository_entries == 16
    assert settings.max_concurrent_analyses == 1
    assert settings.port == 10000
    assert ApiSettings().max_upload_bytes == 512 * 1024 * 1024
    assert ApiSettings().max_repository_entries == 32
    assert ApiSettings().allowed_origins == ()


def test_multiple_origins_trim_whitespace_and_preserve_explicit_allowlist(tmp_path):
    settings = configuration(
        tmp_path,
        SECUREMAILSCOPE_ALLOWED_ORIGINS=f"  {ORIGIN} , https://Other.example:443 , {ORIGIN} ",
    )
    assert settings.api.allowed_origins == (ORIGIN, "https://other.example")


@pytest.mark.parametrize(
    "origin",
    [
        "",
        " ",
        "*",
        ORIGIN + ",",
        "https://*.example.com",
        "https://example.com/path",
        "https://example.com/",
        "https://user:password@example.com",
        "https://example.com?q=1",
        "https://example.com#fragment",
        "https://example.com?",
        "https://example.com#",
        "example.com",
        "http://example.com",
        "https://",
        "https://bad host",
        "https://example.com:abc",
        "https://example.com:65536",
        "https://example.com:0",
        "https://example.com:",
        "https://-bad.example",
        "https://bad..example",
        "https://example.com\\evil",
        "https://example.com\nother",
        "http://localhost:4181",
        "https://localhost",
        "https://127.0.0.1",
        "https://app.localhost",
        "https://127.1",
        "https://2130706433",
        "https://0x7f000001",
        "https://127.0.0.01",
        "https://[fe80::1%eth0]",
        "https://[::1]",
        "http://[::1]:4181",
    ],
)
def test_invalid_or_local_production_origins_are_rejected_without_echo(tmp_path, origin):
    with pytest.raises(DeploymentConfigurationError) as error:
        configuration(tmp_path, SECUREMAILSCOPE_ALLOWED_ORIGINS=origin)
    assert "password" not in str(error.value)


def test_loopback_requires_explicit_local_mode():
    settings = DeploymentSettings.from_environment(
        {"SECUREMAILSCOPE_ALLOWED_ORIGINS": "http://localhost:4181,http://[::1]:4181"},
        local_mode=True,
    )
    assert settings.api.allowed_origins == ("http://localhost:4181", "http://[::1]:4181")
    with pytest.raises(DeploymentConfigurationError):
        DeploymentSettings.from_environment(
            {"SECUREMAILSCOPE_ALLOWED_ORIGINS": "http://external.example"},
            local_mode=True,
        )


@pytest.mark.parametrize(
    "field",
    [
        "SECUREMAILSCOPE_MAX_UPLOAD_BYTES",
        "SECUREMAILSCOPE_MAX_REPOSITORY_ENTRIES",
        "SECUREMAILSCOPE_MAX_CONCURRENT_ANALYSES",
        "PORT",
    ],
)
@pytest.mark.parametrize("value", ["0", "-1", "abc", "1.5", "+1", " 1", "1 ", "true", "１"])
def test_integer_bounds_are_strict(tmp_path, field, value):
    with pytest.raises(DeploymentConfigurationError):
        configuration(tmp_path, **{field: value})


@pytest.mark.parametrize("value", ["65536", "9999999999"])
def test_port_cannot_exceed_tcp_range(tmp_path, value):
    with pytest.raises(DeploymentConfigurationError):
        configuration(tmp_path, PORT=value)


@pytest.mark.parametrize("directory", ["", ".", "../scratch", "/tmp/../scratch", "/"])
def test_tmpdir_must_be_absolute_and_specific(tmp_path, directory):
    with pytest.raises(DeploymentConfigurationError):
        configuration(tmp_path, TMPDIR=directory)


@pytest.mark.parametrize("missing", ["tshark", "capinfos"])
def test_missing_executable_fails_readiness(tmp_path, monkeypatch, missing):
    fake_tools(monkeypatch)
    monkeypatch.setattr(
        deployment.shutil, "which", lambda tool: None if tool == missing else f"/tools/{tool}"
    )
    with pytest.raises(DeploymentReadinessError, match=missing):
        check_readiness(configuration(tmp_path))


def test_non_executable_tool_fails_readiness(tmp_path, monkeypatch):
    fake_tools(monkeypatch)
    monkeypatch.setattr(deployment.os, "access", lambda *args: False)
    with pytest.raises(DeploymentReadinessError, match="not executable"):
        check_readiness(configuration(tmp_path))


@pytest.mark.parametrize("version", ["4.0.9", "3.6.0", "unrecognized"])
def test_incompatible_version_fails(tmp_path, monkeypatch, version):
    fake_tools(monkeypatch, version=version)
    with pytest.raises(DeploymentReadinessError, match="4.2"):
        check_readiness(configuration(tmp_path))


def test_failed_tool_check_is_safe(tmp_path, monkeypatch):
    fake_tools(monkeypatch)

    def fail(*args, **kwargs):
        raise OSError("private executable path and credentials")

    monkeypatch.setattr(deployment, "run_tool", fail)
    with pytest.raises(DeploymentReadinessError, match="version check failed") as error:
        check_readiness(configuration(tmp_path))
    assert "private" not in str(error.value)
    assert "credentials" not in str(error.value)


def test_unwritable_directory_fails_readiness(tmp_path, monkeypatch):
    fake_tools(monkeypatch)

    def denied(*args, **kwargs):
        raise PermissionError("private path")

    monkeypatch.setattr(deployment.tempfile, "TemporaryFile", denied)
    with pytest.raises(DeploymentReadinessError, match="writable private directory"):
        check_readiness(configuration(tmp_path))


def test_directory_with_unsafe_permissions_is_not_repaired(tmp_path, monkeypatch):
    fake_tools(monkeypatch)
    settings = configuration(tmp_path)
    settings.temporary_directory.mkdir(mode=0o755)
    with pytest.raises(DeploymentReadinessError):
        check_readiness(settings)
    assert settings.temporary_directory.stat().st_mode & 0o777 == 0o755


def test_symlink_directory_is_rejected(tmp_path, monkeypatch):
    fake_tools(monkeypatch)
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    settings = configuration(tmp_path)
    settings.temporary_directory.symlink_to(target, target_is_directory=True)
    with pytest.raises(DeploymentReadinessError):
        check_readiness(settings)


def test_valid_tools_and_new_private_directory_pass(tmp_path, monkeypatch):
    calls = fake_tools(monkeypatch)
    settings = configuration(tmp_path)
    assert check_readiness(settings) == {"tshark": "4.2.2", "capinfos": "4.2.2"}
    assert calls == [["/tools/tshark", "--version"], ["/tools/capinfos", "--version"]]
    assert settings.temporary_directory.stat().st_mode & 0o777 == 0o700
    assert settings.temporary_directory.stat().st_uid == os.geteuid()
    assert list(settings.temporary_directory.iterdir()) == []


async def test_readiness_runs_before_serving_and_sets_private_spooling(tmp_path, monkeypatch):
    fake_tools(monkeypatch)
    settings = configuration(tmp_path)
    app = create_deployment_app(settings)
    previous = tempfile.tempdir
    async with app.router.lifespan_context(app):
        assert tempfile.gettempdir() == str(settings.temporary_directory)
        assert app.state.tool_versions == {"tshark": "4.2.2", "capinfos": "4.2.2"}
        assert app.state.api_state.repository.count == 0
    assert tempfile.tempdir == previous


async def test_failed_readiness_prevents_startup(tmp_path, monkeypatch):
    fake_tools(monkeypatch, version="3.0.0")
    app = create_deployment_app(configuration(tmp_path))
    with pytest.raises(DeploymentReadinessError):
        async with app.router.lifespan_context(app):
            pytest.fail("must not serve traffic")


def test_main_uses_validated_port_single_worker_and_no_shell(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREMAILSCOPE_ALLOWED_ORIGINS", ORIGIN)
    monkeypatch.setenv("TMPDIR", str(tmp_path / "private"))
    monkeypatch.setenv("PORT", "18182")
    calls = []
    monkeypatch.setattr(deployment.uvicorn, "run", lambda *args, **kwargs: calls.append(kwargs))
    deployment.main()
    assert calls == [{"host": "0.0.0.0", "port": 18182, "workers": 1, "access_log": False}]
    monkeypatch.setenv("PORT", "10000; secret")
    with pytest.raises(SystemExit, match="PORT") as error:
        deployment.main()
    assert "secret" not in str(error.value)
    assert len(calls) == 1
