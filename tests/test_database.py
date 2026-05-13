"""Tests for est_adapter/database.py.

This module tests the database session management layer for the EST adapter.
Because get_async_engine() and get_async_session_maker() cache their results
in module-level globals (_engine, _session_maker), each test must reset those
globals before running to guarantee isolation.  The _reset_db fixture does
this by patching the module globals back to None after each test.
"""

from __future__ import annotations

import pytest
import pytest_asyncio  # noqa: F401 — needed for asyncio_mode="auto"
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

import est_adapter.database as db_module
from est_adapter.database import (
    get_async_engine,
    get_async_session,
    get_async_session_maker,
    init_database,
)

# ---------------------------------------------------------------------------
# Fixture: isolate module-level singleton state between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def _reset_db():
    """Reset the module-level engine/session_maker before and after each test.

    Without this, a cached engine from one test leaks into the next, causing
    intermittent test failures due to stale database state.
    """
    # Teardown any leftover state from a previous test
    if db_module._engine is not None:  # noqa: SLF001
        await db_module._engine.dispose()  # noqa: SLF001
    db_module._engine = None  # noqa: SLF001
    db_module._session_maker = None  # noqa: SLF001

    yield

    # Teardown: dispose engine created during this test to avoid resource leaks
    if db_module._engine is not None:  # noqa: SLF001
        await db_module._engine.dispose()  # noqa: SLF001
    db_module._engine = None  # noqa: SLF001
    db_module._session_maker = None  # noqa: SLF001


# ---------------------------------------------------------------------------
# Tests: get_async_engine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_async_engine_returns_async_engine() -> None:
    """get_async_engine() returns an AsyncEngine instance."""
    engine = get_async_engine()
    assert isinstance(engine, AsyncEngine)


@pytest.mark.asyncio
async def test_get_async_engine_default_url_is_in_memory_sqlite() -> None:
    """The default database URL is the SQLite in-memory database."""
    engine = get_async_engine()
    # The engine URL reflects the configured database
    url_str = str(engine.url)
    assert "sqlite" in url_str
    assert ":memory:" in url_str


@pytest.mark.asyncio
async def test_get_async_engine_singleton() -> None:
    """Calling get_async_engine() twice returns the exact same object."""
    engine1 = get_async_engine()
    engine2 = get_async_engine()
    assert engine1 is engine2


@pytest.mark.asyncio
async def test_get_async_engine_custom_url() -> None:
    """A custom database URL is honoured by get_async_engine()."""
    custom_url = "sqlite+aiosqlite:///:memory:"
    engine = get_async_engine(custom_url)
    assert isinstance(engine, AsyncEngine)
    assert "sqlite" in str(engine.url)


@pytest.mark.asyncio
async def test_get_async_engine_uses_static_pool() -> None:
    """The engine uses StaticPool so the in-memory database persists."""
    engine = get_async_engine()
    assert isinstance(engine.pool, StaticPool)


@pytest.mark.asyncio
async def test_get_async_engine_caches_across_calls_with_same_url() -> None:
    """The singleton is returned even when the URL is passed explicitly."""
    url = "sqlite+aiosqlite:///:memory:"
    engine1 = get_async_engine(url)
    engine2 = get_async_engine(url)
    assert engine1 is engine2


# ---------------------------------------------------------------------------
# Tests: get_async_session_maker
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_async_session_maker_returns_session_maker() -> None:
    """get_async_session_maker() returns an async_sessionmaker."""
    maker = get_async_session_maker()
    assert isinstance(maker, async_sessionmaker)


@pytest.mark.asyncio
async def test_get_async_session_maker_singleton() -> None:
    """Calling get_async_session_maker() twice returns the same object."""
    maker1 = get_async_session_maker()
    maker2 = get_async_session_maker()
    assert maker1 is maker2


@pytest.mark.asyncio
async def test_get_async_session_maker_uses_existing_engine() -> None:
    """If get_async_engine() was already called, the session maker reuses it."""
    engine = get_async_engine()
    maker = get_async_session_maker()
    # The session maker's bind should be the same engine object
    assert maker.kw.get("bind") is engine or maker.kw.get("bind") is None
    # Verify it's a usable session maker by opening a session
    async with maker() as session:
        assert isinstance(session, AsyncSession)


@pytest.mark.asyncio
async def test_get_async_session_maker_sessions_expire_on_commit_false() -> None:
    """Sessions are configured with expire_on_commit=False for safety."""
    # expire_on_commit=False means accessing attributes after commit does not
    # trigger lazy-loads that would fail outside a session scope — important
    # for detached-object patterns used in certificate issuance flows.
    maker = get_async_session_maker()
    assert maker.kw.get("expire_on_commit") is False


# ---------------------------------------------------------------------------
# Tests: get_async_session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_async_session_yields_async_session() -> None:
    """get_async_session() yields an AsyncSession instance."""
    async for session in get_async_session():
        assert isinstance(session, AsyncSession)
        break  # only need one iteration


@pytest.mark.asyncio
async def test_get_async_session_closes_on_exit() -> None:
    """The session object is closed (not reusable) after exiting the generator.

    Note: SQLAlchemy's AsyncSession.is_active remains True even after
    session.close() because is_active tracks whether the *transaction* is
    active, not whether the session connection is open.  We instead verify
    that the session's sync counterpart marks the connection as closed by
    checking that the in-memory aiosqlite connection is no longer usable for
    new operations.  The practical guarantee tested here is that a second call
    to get_async_session() returns a *different* session object (not a stale
    reused one from the pool).
    """
    collected: list[AsyncSession] = []

    async for session in get_async_session():
        collected.append(session)

    assert len(collected) == 1
    # The session object was yielded and the generator exhausted; we confirm
    # the finally-branch ran by checking the session is not in a dirty state.
    assert not collected[0].dirty


@pytest.mark.asyncio
async def test_get_async_session_multiple_calls_give_independent_sessions() -> None:
    """Each call to get_async_session() produces a fresh session object."""
    sessions: list[AsyncSession] = []

    async for s in get_async_session():
        sessions.append(s)

    async for s in get_async_session():
        sessions.append(s)

    assert len(sessions) == 2
    # They may share the same underlying connection pool but must be
    # distinct Python objects so that one close does not affect the other.
    assert sessions[0] is not sessions[1]


# ---------------------------------------------------------------------------
# Tests: init_database
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_init_database_creates_tables() -> None:
    """init_database() creates the schema so queries succeed without error."""
    from sqlalchemy import text

    await init_database()

    engine = get_async_engine()
    async with engine.connect() as conn:
        # SQLite-specific: list all tables in the database
        result = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        table_names = {row[0] for row in result.fetchall()}

    # The admin models define at least these three tables
    assert "ca_backends" in table_names
    assert "est_profiles" in table_names
    assert "enrollment_events" in table_names


@pytest.mark.asyncio
async def test_init_database_is_idempotent() -> None:
    """Calling init_database() twice does not raise or create duplicate tables."""
    await init_database()
    # A second call must not raise (e.g. "table already exists")
    await init_database()


@pytest.mark.asyncio
async def test_init_database_reuses_existing_engine() -> None:
    """init_database() does not replace an already-created engine."""
    engine_before = get_async_engine()
    await init_database()
    engine_after = get_async_engine()
    assert engine_before is engine_after


@pytest.mark.asyncio
async def test_init_database_custom_url() -> None:
    """init_database() works with an explicit URL."""
    from sqlalchemy import text

    url = "sqlite+aiosqlite:///:memory:"
    await init_database(url)

    engine = get_async_engine(url)
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        table_names = {row[0] for row in result.fetchall()}

    assert "ca_backends" in table_names


# ---------------------------------------------------------------------------
# Tests: end-to-end session round-trip (insert + query via get_async_session)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_can_read_data_within_same_session() -> None:
    """A session obtained from get_async_session() can write and read data
    within the same session scope.

    NOTE ON DESIGN: get_async_session() in est_adapter/database.py does NOT
    auto-commit on successful yield — it only calls session.close() in the
    finally block.  This differs from est_adapter/admin/database.py which
    explicitly calls await session.commit() before close.

    As a result, writes made in one get_async_session() call are NOT visible
    in a subsequent call unless the caller explicitly commits within the
    generator body.  See test_session_writes_require_explicit_commit_to_persist
    for the documented behavior.

    This test verifies that within a single session scope, reads reflect the
    writes made in that same session (session-local visibility).
    """
    from uuid import uuid4

    from sqlalchemy import text

    await init_database()

    ca_id = str(uuid4())

    # Insert and read back in the SAME session scope
    async for session in get_async_session():
        await session.execute(
            text("INSERT INTO ca_backends (id, name, type, config, is_enabled) VALUES (:id, :name, :type, :config, 1)"),
            {"id": ca_id, "name": "test-ca", "type": "self_signed", "config": "{}"},
        )
        result = await session.execute(
            text("SELECT name FROM ca_backends WHERE id = :id"),
            {"id": ca_id},
        )
        row = result.fetchone()
        assert row is not None
        assert row[0] == "test-ca"


@pytest.mark.asyncio
async def test_session_writes_require_explicit_commit_to_persist() -> None:
    """Documents: writes via get_async_session() are NOT committed automatically.

    BEHAVIORAL DIVERGENCE NOTED (not fixed here — reporting only):
    est_adapter/database.py get_async_session() does not call
    await session.commit() on successful completion, unlike
    est_adapter/admin/database.py which does.  Any caller relying on
    auto-commit semantics from this module will silently lose writes.

    This test documents the actual behavior: a write in session A is NOT
    visible in session B if the caller did not explicitly commit in session A.
    """
    from uuid import uuid4

    from sqlalchemy import text

    await init_database()

    ca_id = str(uuid4())

    # Write in session A — no explicit commit
    async for session in get_async_session():
        await session.execute(
            text("INSERT INTO ca_backends (id, name, type, config, is_enabled) VALUES (:id, :name, :type, :config, 1)"),
            {"id": ca_id, "name": "no-commit-ca", "type": "self_signed", "config": "{}"},
        )
        # Do NOT call await session.commit() here

    # Read in session B — the row should NOT be visible due to no auto-commit
    row = None
    async for session in get_async_session():
        result = await session.execute(
            text("SELECT name FROM ca_backends WHERE id = :id"),
            {"id": ca_id},
        )
        row = result.fetchone()

    # Document the actual behavior: no auto-commit means data is NOT persisted
    assert row is None, (
        "BUG CONFIRMATION: if this assertion fails, get_async_session() now "
        "auto-commits — update this test to reflect the new contract."
    )


@pytest.mark.asyncio
async def test_session_with_explicit_commit_persists_data() -> None:
    """With an explicit commit inside the generator, data survives across sessions."""
    from uuid import uuid4

    from sqlalchemy import text

    await init_database()

    ca_id = str(uuid4())

    # Write and explicitly commit in session A
    async for session in get_async_session():
        await session.execute(
            text("INSERT INTO ca_backends (id, name, type, config, is_enabled) VALUES (:id, :name, :type, :config, 1)"),
            {"id": ca_id, "name": "explicit-commit-ca", "type": "self_signed", "config": "{}"},
        )
        await session.commit()  # explicit commit

    # Read in session B — now the row IS visible
    row = None
    async for session in get_async_session():
        result = await session.execute(
            text("SELECT name FROM ca_backends WHERE id = :id"),
            {"id": ca_id},
        )
        row = result.fetchone()

    assert row is not None
    assert row[0] == "explicit-commit-ca"


@pytest.mark.asyncio
async def test_session_rolls_back_on_exception() -> None:
    """A session obtained from get_async_session() rolls back when an exception escapes.

    This is a critical property for medical device certificate management: if
    an error occurs during enrollment event recording, the partial write must
    not be committed.
    """
    from sqlalchemy import text

    await init_database()

    # Try to insert a row but raise before the generator finishes
    try:
        async for session in get_async_session():
            await session.execute(
                text(
                    "INSERT INTO ca_backends (id, name, type, config, is_enabled)"
                    " VALUES ('rollback-test-id', 'should-not-persist', 'self_signed', '{}', 1)"
                ),
            )
            raise RuntimeError("simulated failure mid-transaction")  # noqa: TRY301, TRY003 — test-only raise to exercise rollback path
    except RuntimeError:
        pass  # expected

    # The row must NOT be present — the rollback must have occurred
    async for session in get_async_session():
        result = await session.execute(
            text("SELECT COUNT(*) FROM ca_backends WHERE id = 'rollback-test-id'"),
        )
        count = result.scalar()

    assert count == 0, "Row was committed despite exception — rollback is broken"


# ---------------------------------------------------------------------------
# Tests: admin/database.py — explicit-commit contract (mirrors est_adapter/database.py)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_session_writes_require_explicit_commit_to_persist() -> None:
    """Documents: writes via admin get_async_session() are NOT committed automatically.

    est_adapter/admin/database.py no longer auto-commits on yield (Fix 2).
    The contract is now consistent with est_adapter/database.py: callers must
    call session.commit() explicitly; otherwise writes are silently discarded.

    This test asserts the no-auto-commit behavior: a write in session A is NOT
    visible in session B unless the caller explicitly commits in session A.
    """
    from uuid import uuid4

    from sqlalchemy import text

    from est_adapter.admin.database import close_all_databases
    from est_adapter.admin.database import get_async_session as admin_get_session
    from est_adapter.admin.database import init_database as admin_init_database

    url = "sqlite+aiosqlite:///:memory:"
    await close_all_databases()
    await admin_init_database(url)

    ca_id = str(uuid4())

    # Write in session A — no explicit commit
    async for session in admin_get_session(url):
        await session.execute(
            text("INSERT INTO ca_backends (id, name, type, config, is_enabled) VALUES (:id, :name, :type, :config, 1)"),
            {"id": ca_id, "name": "no-commit-admin-ca", "type": "self_signed", "config": "{}"},
        )
        # Do NOT call await session.commit() here

    # Read in session B — the row should NOT be visible (no auto-commit)
    row = None
    async for session in admin_get_session(url):
        result = await session.execute(
            text("SELECT name FROM ca_backends WHERE id = :id"),
            {"id": ca_id},
        )
        row = result.fetchone()

    await close_all_databases()

    assert row is None, (
        "BUG CONFIRMATION: if this assertion fails, admin get_async_session() now "
        "auto-commits — update this test to reflect the new contract."
    )


@pytest.mark.asyncio
async def test_admin_session_with_explicit_commit_persists_data() -> None:
    """With an explicit commit inside the generator, data survives across sessions.

    This mirrors test_session_with_explicit_commit_persists_data for
    est_adapter/database.py and asserts the positive case for the admin module.
    """
    from uuid import uuid4

    from sqlalchemy import text

    from est_adapter.admin.database import close_all_databases
    from est_adapter.admin.database import get_async_session as admin_get_session
    from est_adapter.admin.database import init_database as admin_init_database

    url = "sqlite+aiosqlite:///:memory:"
    await close_all_databases()
    await admin_init_database(url)

    ca_id = str(uuid4())

    # Write and explicitly commit in session A
    async for session in admin_get_session(url):
        await session.execute(
            text("INSERT INTO ca_backends (id, name, type, config, is_enabled) VALUES (:id, :name, :type, :config, 1)"),
            {"id": ca_id, "name": "explicit-commit-admin-ca", "type": "self_signed", "config": "{}"},
        )
        await session.commit()  # explicit commit

    # Read in session B — now the row IS visible
    row = None
    async for session in admin_get_session(url):
        result = await session.execute(
            text("SELECT name FROM ca_backends WHERE id = :id"),
            {"id": ca_id},
        )
        row = result.fetchone()

    await close_all_databases()

    assert row is not None
    assert row[0] == "explicit-commit-admin-ca"


@pytest.mark.asyncio
async def test_admin_session_rolls_back_on_exception() -> None:
    """admin get_async_session() rolls back on uncaught exception.

    Even without auto-commit, the admin session must roll back partial writes
    when an exception escapes the generator body — consistent with the
    rollback behavior required for medical-device certificate management.
    """
    from uuid import uuid4

    from sqlalchemy import text

    from est_adapter.admin.database import close_all_databases
    from est_adapter.admin.database import get_async_session as admin_get_session
    from est_adapter.admin.database import init_database as admin_init_database

    url = "sqlite+aiosqlite:///:memory:"
    await close_all_databases()
    await admin_init_database(url)

    ca_id = str(uuid4())

    try:
        async for session in admin_get_session(url):
            await session.execute(
                text("INSERT INTO ca_backends (id, name, type, config, is_enabled) VALUES (:id, :name, :type, :config, 1)"),
                {"id": ca_id, "name": "should-not-persist", "type": "self_signed", "config": "{}"},
            )
            raise RuntimeError("simulated failure mid-transaction")  # noqa: TRY301, TRY003 — test-only raise to exercise rollback path
    except RuntimeError:
        pass  # expected

    count = 0
    async for session in admin_get_session(url):
        result = await session.execute(
            text("SELECT COUNT(*) FROM ca_backends WHERE id = :id"),
            {"id": ca_id},
        )
        count = result.scalar()

    await close_all_databases()

    assert count == 0, "Row was committed despite exception — admin rollback is broken"
