import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import boto3
import psycopg2
from psycopg2.extras import Json


def get_db_conn():
    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://privacy:privacy_change_me@postgres:5432/privacy_scrubber",
    )
    return psycopg2.connect(db_url, connect_timeout=3)


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        return int(raw)
    except ValueError:
        return default


def adapters_root() -> Path:
    return Path(os.environ.get("ADAPTERS_PATH", "/app/adapters"))


def find_adapter_manifest_path(adapter_key: str) -> Path:
    root = adapters_root()
    if not root.exists():
        raise RuntimeError(f"adapters path missing: {root}")

    for path in root.rglob("*.adapter.json"):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if manifest.get("key") == adapter_key:
            return path

    raise RuntimeError(f"adapter not found: {adapter_key}")


def load_adapter_manifest(adapter_key: str) -> tuple[dict[str, Any], Path]:
    manifest_path = find_adapter_manifest_path(adapter_key)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return manifest, manifest_path


def poll_reminders() -> None:
    query = """
        select count(*)
        from reminders
        where enabled = true
          and next_run_at <= now();
    """
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            due = cur.fetchone()[0]
    print(f"worker heartbeat: due reminders={due}")


def write_worker_audit_log(action: str, payload: dict[str, Any]) -> None:
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into audit_log (actor_user_id, action, object_type, object_id, payload)
                    values (null, %s, 'system', null, %s::jsonb);
                    """,
                    (action, Json(payload)),
                )
            conn.commit()
    except Exception as exc:  # noqa: BLE001
        print(f"worker audit log failure: {exc}")


def claim_job() -> tuple[str, dict[str, Any]] | None:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                with next_job as (
                  select id
                  from job_queue
                  where job_type = 'adapter_run'
                    and status = 'queued'
                    and available_at <= now()
                  order by created_at asc
                  for update skip locked
                  limit 1
                )
                update job_queue j
                set status = 'running',
                    attempts = attempts + 1,
                    started_at = now()
                from next_job
                where j.id = next_job.id
                returning j.id::text, j.payload::text;
                """
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        return None
    return row[0], json.loads(row[1])


def map_result_status_to_task_status(result_status: str) -> str:
    mapping = {
        "completed": "completed",
        "waiting_manual": "waiting_manual",
        "waiting_email_verification": "waiting_email_verification",
        "failed": "failed",
        "not_applicable": "cancelled",
    }
    return mapping.get(result_status, "failed")


def build_runner_payload(payload: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    task_id = payload["task_id"]
    finding_id = payload["finding_id"]

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  p.id::text,
                  coalesce(p.region_code, ''),
                  f.source_url,
                  f.source_domain
                from findings f
                join profiles p on p.id = f.profile_id
                where f.id = %s::uuid;
                """,
                (finding_id,),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError(f"finding not found for runner payload: {finding_id}")

            profile_id, region_code, source_url, source_domain = row

            cur.execute(
                """
                select id_type::text, encode(value_encrypted, 'base64')
                from identifiers
                where profile_id = %s::uuid
                order by is_primary desc, created_at asc;
                """,
                (profile_id,),
            )
            ids = [{"type": r[0], "value": r[1]} for r in cur.fetchall()]

    return {
        "taskId": task_id,
        "findingId": finding_id,
        "profile": {
            "id": profile_id,
            "regionCode": region_code or None,
        },
        "identifiers": ids,
        "finding": {
            "url": source_url,
            "sourceDomain": source_domain,
        },
        "adapter": {
            "key": manifest.get("key"),
            "version": manifest.get("version"),
            "flowType": manifest.get("flowType", "manual"),
        },
        "action": payload.get("action", "submit_opt_out"),
    }


def run_adapter_command(runner_cmd: list[str], runner_payload: dict[str, Any], working_dir: Path) -> dict[str, Any]:
    proc = subprocess.run(
        runner_cmd,
        input=json.dumps(runner_payload),
        text=True,
        capture_output=True,
        cwd=str(working_dir),
        timeout=int(os.environ.get("ADAPTER_RUN_TIMEOUT_SECONDS", "120")),
        check=False,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"adapter runner failed (code={proc.returncode}) stderr={proc.stderr.strip()[:1200]}"
        )

    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError("adapter runner returned empty stdout")

    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"adapter runner returned invalid JSON: {stdout[:400]}") from exc

    if not isinstance(result, dict):
        raise RuntimeError("adapter runner output must be a JSON object")

    return result


def get_s3_client():
    endpoint = os.environ.get("OBJECT_STORAGE_ENDPOINT", "").strip()
    access_key = os.environ.get("OBJECT_STORAGE_ACCESS_KEY", "").strip()
    secret_key = os.environ.get("OBJECT_STORAGE_SECRET_KEY", "").strip()
    region = os.environ.get("OBJECT_STORAGE_REGION", "us-east-1").strip()

    if not endpoint or not access_key or not secret_key:
        return None

    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def ensure_bucket(client, bucket: str) -> None:
    try:
        client.head_bucket(Bucket=bucket)
        return
    except Exception:
        pass
    client.create_bucket(Bucket=bucket)


def upload_artifacts(adapter_run_id: str, adapter_key: str, artifacts: list[dict[str, Any]], working_dir: Path) -> list[dict[str, Any]]:
    if not artifacts:
        return []

    bucket = os.environ.get("OBJECT_STORAGE_BUCKET", "scrubber-evidence").strip()
    public_base = os.environ.get("OBJECT_STORAGE_PUBLIC_BASE_URL", "").rstrip("/")
    client = get_s3_client()

    if not client or not bucket:
        return artifacts

    ensure_bucket(client, bucket)

    uploaded: list[dict[str, Any]] = []
    for artifact in artifacts:
        path = artifact.get("path")
        if not path:
            uploaded.append(artifact)
            continue

        local_path = Path(path)
        if not local_path.is_absolute():
            local_path = (working_dir / local_path).resolve()

        if not local_path.exists() or not local_path.is_file():
            uploaded.append({**artifact, "upload_error": f"file not found: {local_path}"})
            continue

        key = f"adapter-runs/{adapter_run_id}/{adapter_key}/{local_path.name}"
        content_type = artifact.get("contentType") or "application/octet-stream"

        client.upload_file(
            str(local_path),
            bucket,
            key,
            ExtraArgs={"ContentType": content_type},
        )

        storage_uri = f"s3://{bucket}/{key}"
        item = {
            **artifact,
            "storage_uri": storage_uri,
            "bucket": bucket,
            "key": key,
        }
        if public_base:
            item["url"] = f"{public_base}/{key}"
        uploaded.append(item)

    return uploaded


def resolve_artifact_locator(artifact: dict[str, Any]) -> tuple[str, str] | None:
    bucket = artifact.get("bucket")
    key = artifact.get("key")
    if isinstance(bucket, str) and bucket and isinstance(key, str) and key:
        return bucket, key

    storage_uri = artifact.get("storage_uri")
    if not isinstance(storage_uri, str) or not storage_uri.startswith("s3://"):
        return None

    parsed = urlparse(storage_uri)
    if not parsed.netloc or not parsed.path:
        return None
    return parsed.netloc, parsed.path.lstrip("/")


def cleanup_password_reset_tokens(*, dry_run: bool) -> dict[str, int]:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            if dry_run:
                cur.execute(
                    """
                    select count(*)
                    from password_reset_tokens
                    where expires_at < now() or used_at is not null;
                    """
                )
                return {"candidates": cur.fetchone()[0], "deleted": 0}

            cur.execute(
                """
                with deleted as (
                  delete from password_reset_tokens
                  where expires_at < now() or used_at is not null
                  returning 1
                )
                select count(*) from deleted;
                """
            )
            deleted = cur.fetchone()[0]
        conn.commit()
    return {"candidates": deleted, "deleted": deleted}


def cleanup_refresh_tokens(*, dry_run: bool, revoked_grace_days: int) -> dict[str, int]:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            if dry_run:
                cur.execute(
                    """
                    select count(*)
                    from auth_refresh_tokens
                    where expires_at < now()
                       or (revoked_at is not null and revoked_at < now() - make_interval(days => %s));
                    """,
                    (max(0, revoked_grace_days),),
                )
                return {"candidates": cur.fetchone()[0], "deleted": 0}

            cur.execute(
                """
                with deleted as (
                  delete from auth_refresh_tokens
                  where expires_at < now()
                     or (revoked_at is not null and revoked_at < now() - make_interval(days => %s))
                  returning 1
                )
                select count(*) from deleted;
                """,
                (max(0, revoked_grace_days),),
            )
            deleted = cur.fetchone()[0]
        conn.commit()
    return {"candidates": deleted, "deleted": deleted}


def cleanup_adapter_run_artifacts(*, dry_run: bool, max_age_days: int) -> dict[str, int]:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id::text, artifacts::text
                from adapter_runs
                where finished_at is not null
                  and finished_at < now() - make_interval(days => %s)
                  and status in ('completed', 'failed', 'cancelled', 'not_applicable');
                """,
                (max(0, max_age_days),),
            )
            rows = cur.fetchall()

    run_ids: list[str] = []
    objects_to_delete: list[tuple[str, str]] = []
    for run_id, artifacts_text in rows:
        run_ids.append(run_id)
        try:
            artifacts = json.loads(artifacts_text) if artifacts_text else []
        except json.JSONDecodeError:
            artifacts = []
        if not isinstance(artifacts, list):
            continue
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            locator = resolve_artifact_locator(item)
            if locator:
                objects_to_delete.append(locator)

    if dry_run:
        return {
            "runs_considered": len(run_ids),
            "objects_candidates": len(objects_to_delete),
            "objects_deleted": 0,
            "run_rows_cleared": 0,
        }

    s3 = get_s3_client()
    deleted = 0
    delete_errors = 0
    if objects_to_delete and not s3:
        return {
            "runs_considered": len(run_ids),
            "objects_candidates": len(objects_to_delete),
            "objects_deleted": 0,
            "object_delete_errors": 0,
            "run_rows_cleared": 0,
            "skipped_no_object_storage_client": True,
        }

    for bucket, key in objects_to_delete:
        try:
            assert s3 is not None
            s3.delete_object(Bucket=bucket, Key=key)
            deleted += 1
        except Exception:
            delete_errors += 1

    run_rows_cleared = 0
    if run_ids and delete_errors == 0:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update adapter_runs
                    set artifacts = '[]'::jsonb
                    where id = any(%s::uuid[]);
                    """,
                    (run_ids,),
                )
                run_rows_cleared = cur.rowcount
            conn.commit()

    return {
        "runs_considered": len(run_ids),
        "objects_candidates": len(objects_to_delete),
        "objects_deleted": deleted,
        "object_delete_errors": delete_errors,
        "run_rows_cleared": run_rows_cleared,
    }


def cleanup_idempotency_keys(*, dry_run: bool, max_age_days: int) -> dict[str, int]:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            if dry_run:
                cur.execute(
                    """
                    select count(*)
                    from idempotency_keys
                    where created_at < now() - make_interval(days => %s);
                    """,
                    (max(0, max_age_days),),
                )
                return {"candidates": cur.fetchone()[0], "deleted": 0}

            cur.execute(
                """
                with deleted as (
                  delete from idempotency_keys
                  where created_at < now() - make_interval(days => %s)
                  returning 1
                )
                select count(*) from deleted;
                """,
                (max(0, max_age_days),),
            )
            deleted = cur.fetchone()[0]
        conn.commit()
    return {"candidates": deleted, "deleted": deleted}


def run_retention_cleanup() -> dict[str, Any]:
    dry_run = env_bool("RETENTION_CLEANUP_DRY_RUN", False)
    include_artifacts = env_bool("RETENTION_CLEANUP_INCLUDE_ADAPTER_ARTIFACTS", False)
    include_idempotency = env_bool("RETENTION_CLEANUP_INCLUDE_IDEMPOTENCY_KEYS", True)
    revoked_grace_days = env_int("RETENTION_CLEANUP_REVOKED_REFRESH_GRACE_DAYS", 7)
    artifact_max_age_days = env_int("RETENTION_CLEANUP_ADAPTER_ARTIFACT_MAX_AGE_DAYS", 30)
    idempotency_max_age_days = env_int("RETENTION_CLEANUP_IDEMPOTENCY_MAX_AGE_DAYS", 30)

    started = int(time.time())
    result: dict[str, Any] = {
        "dry_run": dry_run,
        "password_reset_tokens": cleanup_password_reset_tokens(dry_run=dry_run),
        "refresh_tokens": cleanup_refresh_tokens(
            dry_run=dry_run,
            revoked_grace_days=revoked_grace_days,
        ),
    }

    if include_artifacts:
        result["adapter_artifacts"] = cleanup_adapter_run_artifacts(
            dry_run=dry_run,
            max_age_days=artifact_max_age_days,
        )
    else:
        result["adapter_artifacts"] = {"skipped": True}

    if include_idempotency:
        result["idempotency_keys"] = cleanup_idempotency_keys(
            dry_run=dry_run,
            max_age_days=idempotency_max_age_days,
        )
    else:
        result["idempotency_keys"] = {"skipped": True}

    result["duration_seconds"] = max(0, int(time.time()) - started)
    return result


def mark_adapter_run_running(adapter_run_id: str) -> None:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update adapter_runs
                set status = 'running',
                    started_at = coalesce(started_at, now())
                where id = %s::uuid;
                """,
                (adapter_run_id,),
            )
        conn.commit()


def execute_adapter(payload: dict[str, Any]) -> dict[str, Any]:
    adapter_key = payload["adapter_key"]
    action = payload.get("action", "submit_opt_out")
    adapter_run_id = payload["adapter_run_id"]

    manifest, manifest_path = load_adapter_manifest(adapter_key)
    capabilities = manifest.get("capabilities", {})
    flow_type = manifest.get("flowType", "manual")

    if action == "submit_opt_out" and not capabilities.get("submitOptOut", False):
        return {
            "status": "not_applicable",
            "summary": "Adapter does not support submitOptOut.",
            "artifacts": [],
            "raw": {"adapter_key": adapter_key, "flow_type": flow_type},
        }

    runner = manifest.get("runner", {})
    runner_path = runner.get("path") if isinstance(runner, dict) else None

    if not runner_path:
        if flow_type == "manual":
            return {
                "status": "waiting_manual",
                "summary": "Manual adapter: follow playbook.md steps.",
                "artifacts": [],
                "raw": {"adapter_key": adapter_key, "flow_type": flow_type},
            }

        return {
            "status": "waiting_manual",
            "summary": "Adapter has no runner path configured.",
            "artifacts": [],
            "raw": {"adapter_key": adapter_key, "flow_type": flow_type},
        }

    script_path = (manifest_path.parent / runner_path).resolve()
    if not script_path.exists():
        raise RuntimeError(f"runner script not found: {script_path}")

    with tempfile.TemporaryDirectory(prefix="adapter-run-") as tmpdir:
        run_dir = Path(tmpdir)
        runner_payload = build_runner_payload(payload, manifest)
        runner_payload["workDir"] = str(run_dir)

        cmd = ["python", str(script_path)]
        for arg in runner.get("args", []):
            cmd.append(str(arg))

        result = run_adapter_command(cmd, runner_payload, working_dir=run_dir)
        artifacts = result.get("artifacts", [])
        if not isinstance(artifacts, list):
            artifacts = []

        uploaded = upload_artifacts(adapter_run_id, adapter_key, artifacts, working_dir=run_dir)
        result["artifacts"] = uploaded
        result.setdefault("raw", {})
        result["raw"]["runner_script"] = str(script_path)

        return result


def complete_job_success(job_id: str, payload: dict[str, Any], result: dict[str, Any]) -> None:
    adapter_run_id = payload["adapter_run_id"]
    task_id = payload["task_id"]
    task_status = map_result_status_to_task_status(result.get("status", "failed"))

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update adapter_runs
                set status = %s,
                    summary = %s,
                    artifacts = %s::jsonb,
                    raw_result = %s::jsonb,
                    error_text = null,
                    started_at = coalesce(started_at, now()),
                    finished_at = now()
                where id = %s::uuid;
                """,
                (
                    result.get("status", "failed"),
                    result.get("summary", ""),
                    Json(result.get("artifacts", [])),
                    Json(result.get("raw", {})),
                    adapter_run_id,
                ),
            )
            cur.execute(
                """
                update tasks
                set status = %s::task_status,
                    result_summary = %s,
                    completed_at = case when %s::task_status = 'completed' then now() else completed_at end
                where id = %s::uuid;
                """,
                (task_status, result.get("summary", ""), task_status, task_id),
            )
            cur.execute(
                """
                update job_queue
                set status = 'completed',
                    finished_at = now(),
                    last_error = null
                where id = %s::uuid;
                """,
                (job_id,),
            )
        conn.commit()


def complete_job_failure(job_id: str, payload: dict[str, Any], error_text: str) -> None:
    adapter_run_id = payload.get("adapter_run_id")
    task_id = payload.get("task_id")

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update job_queue
                set status = 'failed',
                    finished_at = now(),
                    last_error = %s
                where id = %s::uuid;
                """,
                (error_text[:4000], job_id),
            )
            if adapter_run_id:
                cur.execute(
                    """
                    update adapter_runs
                    set status = 'failed',
                        error_text = %s,
                        finished_at = now()
                    where id = %s::uuid;
                    """,
                    (error_text[:4000], adapter_run_id),
                )
            if task_id:
                cur.execute(
                    """
                    update tasks
                    set status = 'failed'::task_status,
                        result_summary = %s
                    where id = %s::uuid;
                    """,
                    (error_text[:4000], task_id),
                )
        conn.commit()


def process_one_job() -> bool:
    claimed = claim_job()
    if not claimed:
        return False

    job_id, payload = claimed
    try:
        mark_adapter_run_running(payload["adapter_run_id"])
        result = execute_adapter(payload)
        complete_job_success(job_id, payload, result)
        print(f"job completed: {job_id} status={result.get('status')}")
    except Exception as exc:  # noqa: BLE001
        complete_job_failure(job_id, payload, str(exc))
        print(f"job failed: {job_id} error={exc}")
    return True


def main() -> None:
    interval = int(os.environ.get("WORKER_INTERVAL_SECONDS", "60"))
    retention_enabled = env_bool("RETENTION_CLEANUP_ENABLED", True)
    retention_interval = env_int("RETENTION_CLEANUP_INTERVAL_SECONDS", 3600)
    last_retention_run = 0.0
    print("worker started")

    while True:
        try:
            poll_reminders()
            if retention_enabled and (time.time() - last_retention_run) >= max(30, retention_interval):
                retention_result = run_retention_cleanup()
                write_worker_audit_log("retention.cleanup.run", retention_result)
                print(f"retention cleanup: {json.dumps(retention_result)}")
                last_retention_run = time.time()
            processed = process_one_job()
            if processed:
                continue
        except Exception as exc:  # noqa: BLE001
            print(f"worker error: {exc}")
        time.sleep(interval)


if __name__ == "__main__":
    main()
