from __future__ import annotations

import os

import pytest


def test_idempotency_retention_cleanup_dry_run_and_delete():
    psycopg2 = pytest.importorskip("psycopg2")
    workers_runner = pytest.importorskip("workers.runner")
    cleanup_idempotency_keys = workers_runner.cleanup_idempotency_keys

    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://privacy:privacy_change_me@localhost:5432/privacy_scrubber",
    )

    old_key = "pytest-idem-retention-old"
    fresh_key = "pytest-idem-retention-fresh"

    with psycopg2.connect(db_url, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("delete from idempotency_keys where idempotency_key in (%s, %s);", (old_key, fresh_key))
            cur.execute(
                """
                insert into idempotency_keys (
                  scope_key, endpoint, idempotency_key, request_hash, response_status, response_body, created_at
                )
                values
                  (%s, %s, %s, %s, 200, '{}'::jsonb, now() - interval '40 days'),
                  (%s, %s, %s, %s, 200, '{}'::jsonb, now());
                """,
                (
                    "user:test-retention",
                    "providers.create",
                    old_key,
                    "hash-old",
                    "user:test-retention",
                    "providers.create",
                    fresh_key,
                    "hash-fresh",
                ),
            )
        conn.commit()

    dry = cleanup_idempotency_keys(dry_run=True, max_age_days=30)
    assert dry["candidates"] >= 1
    assert dry["deleted"] == 0

    deleted = cleanup_idempotency_keys(dry_run=False, max_age_days=30)
    assert deleted["deleted"] >= 1

    with psycopg2.connect(db_url, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("select count(*) from idempotency_keys where idempotency_key = %s;", (old_key,))
            old_count = cur.fetchone()[0]
            cur.execute("select count(*) from idempotency_keys where idempotency_key = %s;", (fresh_key,))
            fresh_count = cur.fetchone()[0]
            cur.execute("delete from idempotency_keys where idempotency_key in (%s, %s);", (old_key, fresh_key))
        conn.commit()

    assert old_count == 0
    assert fresh_count == 1
