from __future__ import annotations

from typing import Any


def _create_profile(api, owner_user_id: str, run_key: str) -> str:
    profile = api.json(
        "POST",
        "/v1/profiles",
        json={
            "owner_user_id": owner_user_id,
            "display_name": f"Pytest Lifecycle {run_key}",
            "region_code": "US-CA",
        },
        expected_status=200,
    )
    return profile["id"]


def _paginate(api, path: str, query: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    query = query or {}
    query = {**query, "limit": 2}

    first = api.json("GET", path, params=query, expected_status=200)
    first_items = first["items"]
    assert len(first_items) <= 2

    cursor = first.get("next_cursor")
    if not cursor:
        return first_items

    second = api.json("GET", path, params={**query, "cursor": cursor}, expected_status=200)
    second_items = second["items"]
    assert len(second_items) <= 2

    first_ids = {item["id"] for item in first_items}
    second_ids = {item["id"] for item in second_items}
    assert first_ids.isdisjoint(second_ids)

    return first_items + second_items


def _audit_items(api, limit: int = 500) -> list[dict[str, Any]]:
    page = api.json("GET", "/v1/audit-log", params={"limit": limit}, expected_status=200)
    return page["items"]


def _assert_audit_action_for_object(
    api,
    *,
    action: str,
    object_id: str,
    payload_contains: dict[str, Any] | None = None,
) -> None:
    payload_contains = payload_contains or {}
    items = _audit_items(api)
    matches = [it for it in items if it.get("action") == action and it.get("object_id") == object_id]
    assert matches, f"missing audit event action={action} object_id={object_id}"
    payload = matches[0].get("payload", {}) or {}
    for key, expected in payload_contains.items():
        assert payload.get(key) == expected, f"audit payload mismatch for {action}.{key}"


def test_provider_and_adapter_crud(api, owner_user_id: str, run_key: str):
    # owner_user_id fixture ensures auth and cleanup path have baseline data.
    assert owner_user_id

    provider_key = f"pytest_provider_{run_key}"
    provider = api.json(
        "POST",
        "/v1/providers",
        json={
            "key": provider_key,
            "kind": "search_provider",
            "enabled": True,
            "config": {"endpoint": "https://provider.example"},
        },
        expected_status=200,
    )
    assert provider["key"] == provider_key
    assert provider["enabled"] is True
    _assert_audit_action_for_object(
        api,
        action="providers.create",
        object_id=provider["id"],
        payload_contains={"key": provider_key},
    )

    provider_updated = api.json(
        "PATCH",
        f"/v1/providers/{provider['id']}",
        json={"enabled": False, "config": {"endpoint": "https://provider2.example"}},
        expected_status=200,
    )
    assert provider_updated["enabled"] is False
    assert provider_updated["config"]["endpoint"] == "https://provider2.example"
    _assert_audit_action_for_object(
        api,
        action="providers.update",
        object_id=provider["id"],
        payload_contains={"key": provider_key},
    )

    adapter_key = f"pytest_adapter_{run_key}"
    adapter = api.json(
        "POST",
        "/v1/adapters",
        json={
            "key": adapter_key,
            "display_name": "Pytest Adapter",
            "domain": "example.test",
            "flow": "manual",
            "adapter_version": "1.0.0",
            "enabled": True,
            "metadata": {"source": "pytest"},
        },
        expected_status=200,
    )
    assert adapter["key"] == adapter_key
    assert adapter["flow"] == "manual"
    _assert_audit_action_for_object(
        api,
        action="adapters.create",
        object_id=adapter["id"],
        payload_contains={"key": adapter_key},
    )

    adapter_updated = api.json(
        "PATCH",
        f"/v1/adapters/{adapter['id']}",
        json={"enabled": False, "adapter_version": "1.0.1"},
        expected_status=200,
    )
    assert adapter_updated["enabled"] is False
    assert adapter_updated["adapter_version"] == "1.0.1"
    _assert_audit_action_for_object(
        api,
        action="adapters.update",
        object_id=adapter["id"],
        payload_contains={"key": adapter_key},
    )

    providers_page = _paginate(api, "/v1/providers")
    assert any(item["key"] == provider_key for item in providers_page)

    adapters_page = _paginate(api, "/v1/adapters")
    assert any(item["key"] == adapter_key for item in adapters_page)


def test_findings_tasks_reminders_lifecycle_and_pagination(api, owner_user_id: str, run_key: str):
    profile_id = _create_profile(api, owner_user_id, run_key)

    finding_ids: list[str] = []
    for i in range(3):
        finding = api.json(
            "POST",
            "/v1/findings",
            json={
                "profile_id": profile_id,
                "source_domain": f"pytest{i}.example.test",
                "source_url": f"https://pytest{i}.example.test/profile/{run_key}",
                "risk_score": 50 + i,
                "matched_identifiers": ["full_name"],
                "exposed_fields": ["name"],
                "notes": f"fixture-{i}-{run_key}",
            },
            expected_status=200,
        )
        finding_ids.append(finding["id"])
        updated = api.json(
            "PATCH",
            f"/v1/findings/{finding['id']}",
            json={"status": "triaged", "risk_score": 60 + i},
            expected_status=200,
        )
        assert updated["status"] == "triaged"
        _assert_audit_action_for_object(
            api,
            action="findings.create",
            object_id=finding["id"],
        )
        _assert_audit_action_for_object(
            api,
            action="findings.update",
            object_id=finding["id"],
            payload_contains={"new_status": "triaged"},
        )

    task_ids: list[str] = []
    for finding_id in finding_ids:
        task = api.json(
            "POST",
            "/v1/tasks",
            json={"finding_id": finding_id},
            expected_status=200,
        )
        task_ids.append(task["id"])
        task_updated = api.json(
            "PATCH",
            f"/v1/tasks/{task['id']}",
            json={"status": "in_progress", "result_summary": "pytest updated"},
            expected_status=200,
        )
        assert task_updated["status"] == "in_progress"
        _assert_audit_action_for_object(
            api,
            action="tasks.create",
            object_id=task["id"],
        )
        _assert_audit_action_for_object(
            api,
            action="tasks.update",
            object_id=task["id"],
            payload_contains={"new_status": "in_progress"},
        )

    reminder_ids: list[str] = []
    for finding_id in finding_ids:
        reminder = api.json(
            "POST",
            "/v1/reminders",
            json={
                "profile_id": profile_id,
                "finding_id": finding_id,
                "reminder_type": "monthly_recheck",
                "next_run_at": "2030-01-01T00:00:00Z",
                "interval_days": 30,
                "enabled": True,
                "metadata": {"source": "pytest"},
            },
            expected_status=200,
        )
        reminder_ids.append(reminder["id"])
        _assert_audit_action_for_object(
            api,
            action="reminders.create",
            object_id=reminder["id"],
        )

    reminder_updated = api.json(
        "PATCH",
        f"/v1/reminders/{reminder_ids[0]}",
        json={"enabled": False},
        expected_status=200,
    )
    assert reminder_updated["enabled"] is False
    _assert_audit_action_for_object(
        api,
        action="reminders.update",
        object_id=reminder_ids[0],
        payload_contains={"new_enabled": False},
    )

    findings_page = _paginate(api, "/v1/findings", {"profile_id": profile_id})
    findings_in_profile = [item for item in findings_page if item["profile_id"] == profile_id]
    assert findings_in_profile

    tasks_page = _paginate(api, "/v1/tasks")
    task_statuses = {item["status"] for item in tasks_page if item["id"] in set(task_ids)}
    assert "in_progress" in task_statuses

    reminders_page = _paginate(api, "/v1/reminders", {"profile_id": profile_id})
    reminder_ids_page = {item["id"] for item in reminders_page}
    assert any(rid in reminder_ids_page for rid in reminder_ids)

    # Validate cursor-enabled system lists return shape.
    for path in ["/v1/audit-log", "/v1/adapter-runs", "/v1/jobs"]:
        page = api.json("GET", path, params={"limit": 2}, expected_status=200)
        assert "items" in page
        assert "next_cursor" in page
