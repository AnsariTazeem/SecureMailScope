"""Safe local SQLite configuration for future relational adapters.

Configuration validation and Engine construction are side-effect free. Every
new DBAPI connection revalidates the target. On POSIX, a missing database file
is prepared atomically with owner-only permissions before SQLite opens it.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import URL

SQLITE_DATABASE_PATH_ENV = "SECUREMAILSCOPE_SQLITE_PATH"
DEFAULT_SQLITE_BUSY_TIMEOUT_MS = 5_000
MAX_SQLITE_BUSY_TIMEOUT_MS = 60_000
_UNSAFE_FILE_PERMISSION_BITS = stat.S_IRWXG | stat.S_IRWXO
_UNSAFE_PARENT_WRITE_BITS = stat.S_IWGRP | stat.S_IWOTH


class DatabaseConfigurationError(ValueError):
    """A fixed, path-safe failure for invalid relational configuration."""


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _FileIdentity:
        return cls(device=value.st_dev, inode=value.st_ino)


@dataclass(slots=True)
class _PreparedSQLiteTarget:
    """Open POSIX descriptors retained across the SQLite open operation."""

    parent_fd: int
    database_fd: int
    parent_identity: _FileIdentity
    database_identity: _FileIdentity

    def close(self) -> None:
        for descriptor in (self.database_fd, self.parent_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class SQLiteDatabaseConfig:
    """Validated local file configuration for SQLite.

    The path must be absolute, all existing components must be non-symlinks,
    and its parent must already exist and be writable/searchable. On POSIX,
    the immediate parent must be application-owned and not group/world
    writable; an existing database must be application-owned, readable and
    writable, and grant no group/other permissions.
    """

    database_path: Path
    busy_timeout_ms: int = DEFAULT_SQLITE_BUSY_TIMEOUT_MS

    def __post_init__(self) -> None:
        self._validate_timeout(self.busy_timeout_ms)
        if not isinstance(self.database_path, Path):
            raise DatabaseConfigurationError("SQLite database path is invalid")
        self._validate_path(self.database_path)

    @classmethod
    def from_path(
        cls,
        database_path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
    ) -> SQLiteDatabaseConfig:
        try:
            path = Path(database_path)
        except (TypeError, ValueError, OSError):
            raise DatabaseConfigurationError("SQLite database path is invalid") from None
        return cls(database_path=path, busy_timeout_ms=busy_timeout_ms)

    @classmethod
    def from_environment(cls) -> SQLiteDatabaseConfig:
        value = os.environ.get(SQLITE_DATABASE_PATH_ENV)
        if not value:
            raise DatabaseConfigurationError("SQLite database path is required")
        return cls.from_path(value)

    @property
    def sqlalchemy_url(self) -> URL:
        """Build a SQLAlchemy URL without manual string interpolation."""
        return URL.create("sqlite+pysqlite", database=str(self.database_path))

    @staticmethod
    def _validate_timeout(timeout_ms: int) -> None:
        if (
            isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, int)
            or not 1 <= timeout_ms <= MAX_SQLITE_BUSY_TIMEOUT_MS
        ):
            raise DatabaseConfigurationError("SQLite busy timeout is invalid")

    @classmethod
    def _validate_path(cls, path: Path) -> None:
        try:
            if not path.is_absolute():
                raise DatabaseConfigurationError("SQLite database path must be absolute")
            if str(path) == ":memory:" or "\x00" in str(path):
                raise DatabaseConfigurationError("SQLite database path is invalid")
            cls._reject_symlink_components(path)

            parent = path.parent
            parent_stat = os.stat(parent, follow_symlinks=False)
            if not stat.S_ISDIR(parent_stat.st_mode):
                raise DatabaseConfigurationError("SQLite database parent is unavailable")
            if not os.access(parent, os.W_OK | os.X_OK):
                raise DatabaseConfigurationError("SQLite database parent is not writable")
            if os.name == "posix":
                cls._validate_posix_parent(parent_stat)

            try:
                file_stat = os.stat(path, follow_symlinks=False)
            except FileNotFoundError:
                return
            cls._validate_existing_file_stat(file_stat)
            if not os.access(path, os.R_OK | os.W_OK):
                raise DatabaseConfigurationError("SQLite database file is not writable")
        except DatabaseConfigurationError:
            raise
        except OSError:
            raise DatabaseConfigurationError("SQLite database path is invalid") from None

    @staticmethod
    def _reject_symlink_components(path: Path) -> None:
        current = Path(path.anchor)
        for component in path.parts[1:]:
            current /= component
            try:
                component_stat = os.lstat(current)
            except FileNotFoundError:
                if current == path:
                    return
                raise DatabaseConfigurationError("SQLite database parent is unavailable") from None
            if stat.S_ISLNK(component_stat.st_mode):
                raise DatabaseConfigurationError("SQLite database path contains a symlink")

    @staticmethod
    def _validate_posix_parent(parent_stat: os.stat_result) -> None:
        if parent_stat.st_uid != os.geteuid():
            raise DatabaseConfigurationError("SQLite database parent permissions are unsafe")
        if stat.S_IMODE(parent_stat.st_mode) & _UNSAFE_PARENT_WRITE_BITS:
            raise DatabaseConfigurationError("SQLite database parent permissions are unsafe")

    @staticmethod
    def _validate_existing_file_stat(file_stat: os.stat_result) -> None:
        if not stat.S_ISREG(file_stat.st_mode):
            raise DatabaseConfigurationError("SQLite database target is invalid")
        if os.name != "posix":
            return
        mode = stat.S_IMODE(file_stat.st_mode)
        if file_stat.st_uid != os.geteuid() or mode & _UNSAFE_FILE_PERMISSION_BITS:
            raise DatabaseConfigurationError("SQLite database file permissions are unsafe")
        if mode & (stat.S_IRUSR | stat.S_IWUSR) != (stat.S_IRUSR | stat.S_IWUSR):
            raise DatabaseConfigurationError("SQLite database file is not writable")


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _file_open_flags() -> int:
    flags = os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _open_posix_parent(path: Path) -> int:
    """Traverse the configured absolute parent without following symlinks."""
    descriptor = -1
    try:
        descriptor = os.open(path.anchor, _directory_open_flags())
        for component in path.parent.parts[1:]:
            next_descriptor = os.open(
                component,
                _directory_open_flags(),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise DatabaseConfigurationError("SQLite database path is invalid") from None


def _prepare_posix_target(settings: SQLiteDatabaseConfig) -> _PreparedSQLiteTarget:
    """Open or atomically create the exact target under a secured parent FD."""
    path = settings.database_path
    parent_fd = _open_posix_parent(path)
    database_fd = -1
    try:
        parent_stat = os.fstat(parent_fd)
        settings._validate_posix_parent(parent_stat)
        if os.access in os.supports_fd and not os.access(parent_fd, os.W_OK | os.X_OK):
            raise DatabaseConfigurationError("SQLite database parent is not writable")

        try:
            candidate_stat = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            creation_flags = _file_open_flags() | os.O_CREAT | os.O_EXCL
            database_fd = os.open(path.name, creation_flags, 0o600, dir_fd=parent_fd)
            os.fchmod(database_fd, 0o600)
        else:
            settings._validate_existing_file_stat(candidate_stat)
            database_fd = os.open(path.name, _file_open_flags(), dir_fd=parent_fd)

        database_stat = os.fstat(database_fd)
        settings._validate_existing_file_stat(database_stat)
        return _PreparedSQLiteTarget(
            parent_fd=parent_fd,
            database_fd=database_fd,
            parent_identity=_FileIdentity.from_stat(parent_stat),
            database_identity=_FileIdentity.from_stat(database_stat),
        )
    except DatabaseConfigurationError:
        _close_descriptor(database_fd)
        _close_descriptor(parent_fd)
        raise
    except OSError:
        _close_descriptor(database_fd)
        _close_descriptor(parent_fd)
        raise DatabaseConfigurationError("SQLite database target preparation failed") from None


def _close_descriptor(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _verify_prepared_posix_target(
    settings: SQLiteDatabaseConfig,
    prepared: _PreparedSQLiteTarget,
) -> None:
    """Detect parent or target replacement around SQLite's own path open."""
    try:
        settings._validate_path(settings.database_path)
        absolute_parent = os.stat(settings.database_path.parent, follow_symlinks=False)
        relative_file = os.stat(
            settings.database_path.name,
            dir_fd=prepared.parent_fd,
            follow_symlinks=False,
        )
        absolute_file = os.stat(settings.database_path, follow_symlinks=False)
        if _FileIdentity.from_stat(absolute_parent) != prepared.parent_identity:
            raise DatabaseConfigurationError("SQLite database target changed during connection")
        if _FileIdentity.from_stat(relative_file) != prepared.database_identity:
            raise DatabaseConfigurationError("SQLite database target changed during connection")
        if _FileIdentity.from_stat(absolute_file) != prepared.database_identity:
            raise DatabaseConfigurationError("SQLite database target changed during connection")
    except DatabaseConfigurationError:
        raise
    except OSError:
        raise DatabaseConfigurationError(
            "SQLite database target changed during connection"
        ) from None


def _connect_sqlite(settings: SQLiteDatabaseConfig) -> sqlite3.Connection:
    """Revalidate and securely prepare the configured target, then connect."""
    settings._validate_path(settings.database_path)
    prepared = _prepare_posix_target(settings) if os.name == "posix" else None
    connection: sqlite3.Connection | None = None
    try:
        if prepared is not None:
            _verify_prepared_posix_target(settings, prepared)
        connection = sqlite3.connect(
            settings.database_path,
            timeout=settings.busy_timeout_ms / 1_000,
        )
        if prepared is not None:
            _verify_prepared_posix_target(settings, prepared)
        else:
            settings._validate_path(settings.database_path)
        return connection
    except DatabaseConfigurationError:
        if connection is not None:
            connection.close()
        raise
    except (OSError, sqlite3.Error):
        if connection is not None:
            connection.close()
        raise DatabaseConfigurationError("SQLite database connection failed") from None
    finally:
        if prepared is not None:
            prepared.close()


def create_sqlite_engine(settings: SQLiteDatabaseConfig) -> Engine:
    """Create a lazy SQLAlchemy Engine with bounded local SQLite behavior.

    Foreign-key enforcement is enabled for every DBAPI connection, including
    migration connections. The SQLite lock timeout is bounded. WAL is
    intentionally not enabled by this foundation.
    """
    if not isinstance(settings, SQLiteDatabaseConfig):
        raise DatabaseConfigurationError("SQLite database configuration is invalid")

    engine = create_engine(
        settings.sqlalchemy_url,
        creator=lambda: _connect_sqlite(settings),
    )

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(
        dbapi_connection: sqlite3.Connection,
        connection_record: object,
    ) -> None:
        del connection_record
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.execute("PRAGMA foreign_keys")
            enabled = cursor.fetchone()
            if enabled != (1,):
                raise DatabaseConfigurationError("SQLite foreign-key enforcement is unavailable")
        finally:
            cursor.close()

    return engine
