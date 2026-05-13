import { expect, test } from "@playwright/test";

test("ui renders passkey controls and uses mocked API wiring", async ({ page }) => {
  await page.route("**/v1/auth/login", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        access_token: "mocktoken",
        token_type: "bearer",
        user: { email: "qa@example.com", role: "owner" },
      }),
    });
  });

  await page.route("**/v1/auth/me", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        auth_type: "jwt",
        email: "qa@example.com",
        role: "owner",
      }),
    });
  });

  await page.route("**/v1/auth/mfa/webauthn/credentials", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            credential_id: "cred_test_1",
            nickname: "Laptop Passkey",
            last_used_at: null,
            sign_count: 1,
          },
          {
            credential_id: "cred_test_2",
            nickname: "Phone Passkey",
            last_used_at: "2026-05-13T00:00:00Z",
            sign_count: 2,
          },
        ],
      }),
    });
  });

  await page.route("**/v1/audit-log?**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            id: "audit_1",
            actor_user_id: "user_1",
            action: "users.update_role",
            object_type: "user",
            object_id: "obj_1",
            payload: { old_role: "viewer", new_role: "operator" },
            created_at: "2026-05-13T00:00:00Z",
          },
        ],
        next_cursor: null,
      }),
    });
  });

  await page.route("**/v1/profiles", async (route) => {
    if (route.request().method() !== "GET") return route.fallback();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            id: "profile_1",
            owner_user_id: "user_1",
            display_name: "Demo Profile",
            region_code: "US-CA",
            status: "active",
            created_at: "2026-05-13T00:00:00Z",
            updated_at: "2026-05-13T00:00:00Z",
          },
        ],
      }),
    });
  });

  await page.route("**/v1/profiles/profile_1/identifiers", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            id: "identifier_1",
            id_type: "email",
            is_primary: true,
            hash_prefix: "abc123def456",
            created_at: "2026-05-13T00:00:00Z",
          },
        ],
      }),
    });
  });

  await page.route("**/v1/findings?**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            id: "finding_1",
            profile_id: "profile_1",
            scan_id: null,
            adapter_id: null,
            source_domain: "example-broker.test",
            source_url: "https://example-broker.test/p/1",
            matched_identifiers: ["email"],
            exposed_fields: ["email"],
            risk_score: 70,
            status: "new",
            first_seen_at: "2026-05-13T00:00:00Z",
            last_seen_at: "2026-05-13T00:00:00Z",
            removed_at: null,
            notes: "seed finding",
          },
        ],
        next_cursor: null,
      }),
    });
  });

  await page.route("**/v1/tasks?**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            id: "task_1",
            finding_id: "finding_1",
            adapter_id: null,
            adapter_key: "manual_test_adapter",
            assigned_user_id: null,
            status: "open",
            due_at: "2026-05-20T00:00:00Z",
            completed_at: null,
            result_summary: null,
            metadata: {},
            created_at: "2026-05-13T00:00:00Z",
            updated_at: "2026-05-13T00:00:00Z",
          },
        ],
        next_cursor: null,
      }),
    });
  });

  await page.route("**/v1/reminders?**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            id: "reminder_1",
            profile_id: "profile_1",
            finding_id: "finding_1",
            reminder_type: "recheck",
            next_run_at: "2026-06-01T00:00:00Z",
            interval_days: 30,
            enabled: true,
            metadata: { channel: "email" },
            created_at: "2026-05-13T00:00:00Z",
          },
        ],
        next_cursor: null,
      }),
    });
  });

  await page.goto("/ui");

  await expect(page.getByRole("button", { name: "Login With Passkey" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Enroll Passkey" })).toBeVisible();
  await expect(page.getByRole("button", { name: "List Passkeys" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy Selected ID" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reveal Details" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete Selected Passkey" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load Audit Log" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load Profiles" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load Findings" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load Tasks" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load Reminders" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Export Filtered JSON" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy Curl Example" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Clear Sensitive UI Data" })).toBeVisible();

  await page.fill("#email", "qa@example.com");
  await page.fill("#password", "StrongPassw0rd!123");
  await page.locator("#login-form button[type='submit']").click();
  await expect(page.locator("#auth-output")).toContainText("mocktoken");

  await page.getByRole("button", { name: "Refresh Me" }).click();
  await expect(page.locator("#auth-output")).toContainText("qa@example.com");

  await page.getByRole("button", { name: "List Passkeys" }).click();
  await expect(page.locator("#webauthn_credential_select option")).toHaveCount(3);

  await page.selectOption("#webauthn_credential_select", "cred_test_2");
  await page.getByRole("button", { name: "Reveal Details" }).click();
  await expect(page.locator("#webauthn-output")).toContainText("Phone Passkey");

  await page.getByRole("button", { name: "Load Audit Log" }).click();
  await expect(page.locator("#audit-output")).toContainText("users.update_role");

  await page.getByRole("button", { name: "Load Profiles" }).click();
  await expect(page.locator("#profiles-output")).toContainText("Demo Profile");

  await page.selectOption("#profiles-select", "profile_1");
  await page.getByRole("button", { name: "Load Selected Profile Identifiers" }).click();
  await expect(page.locator("#profiles-output")).toContainText("identifier_1");

  await page.getByRole("button", { name: "Load Findings" }).click();
  await expect(page.locator("#findings-output")).toContainText("finding_1");

  await page.getByRole("button", { name: "Load Tasks" }).click();
  await expect(page.locator("#tasks-output")).toContainText("task_1");

  await page.getByRole("button", { name: "Load Reminders" }).click();
  await expect(page.locator("#reminders-output")).toContainText("reminder_1");

  await page.getByRole("button", { name: "Clear Sensitive UI Data" }).click();
  await expect(page.locator("#api-keys-output")).toContainText("cleared");
});

test("ui task/reminder actions send expected payloads", async ({ page }) => {
  const taskItems = [
    {
      id: "task_1",
      finding_id: "finding_1",
      adapter_id: null,
      adapter_key: "manual_test_adapter",
      assigned_user_id: null,
      status: "open",
      due_at: "2026-05-20T00:00:00Z",
      completed_at: null,
      result_summary: null,
      metadata: {},
      created_at: "2026-05-13T00:00:00Z",
      updated_at: "2026-05-13T00:00:00Z",
    },
  ];
  const reminderItems = [
    {
      id: "reminder_1",
      profile_id: "profile_1",
      finding_id: "finding_1",
      reminder_type: "recheck",
      next_run_at: "2026-06-01T00:00:00Z",
      interval_days: 30,
      enabled: true,
      metadata: { channel: "email" },
      created_at: "2026-05-13T00:00:00Z",
    },
  ];
  let createTaskBody = null;
  let updateTaskBody = null;
  let queueTaskBody = null;
  let createReminderBody = null;
  let updateReminderBody = null;

  await page.route("**/v1/auth/login", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        access_token: "mocktoken",
        token_type: "bearer",
        user: { email: "qa@example.com", role: "owner" },
      }),
    });
  });

  await page.route("**/v1/auth/me", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        auth_type: "jwt",
        email: "qa@example.com",
        role: "owner",
      }),
    });
  });

  await page.route("**/v1/api-keys", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ items: [] }),
    });
  });

  await page.route("**/v1/profiles", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            id: "profile_1",
            owner_user_id: "user_1",
            display_name: "Demo Profile",
            region_code: "US-CA",
            status: "active",
            created_at: "2026-05-13T00:00:00Z",
            updated_at: "2026-05-13T00:00:00Z",
          },
        ],
      }),
    });
  });

  await page.route("**/v1/findings?**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            id: "finding_1",
            profile_id: "profile_1",
            scan_id: null,
            adapter_id: null,
            source_domain: "example-broker.test",
            source_url: "https://example-broker.test/p/1",
            matched_identifiers: ["email"],
            exposed_fields: ["email"],
            risk_score: 70,
            status: "new",
            first_seen_at: "2026-05-13T00:00:00Z",
            last_seen_at: "2026-05-13T00:00:00Z",
            removed_at: null,
            notes: "seed finding",
          },
        ],
        next_cursor: null,
      }),
    });
  });

  await page.route("**/v1/tasks?**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: taskItems,
        next_cursor: null,
      }),
    });
  });

  await page.route("**/v1/tasks", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    createTaskBody = JSON.parse(route.request().postData() || "{}");
    expect(createTaskBody).toEqual({
      finding_id: "finding_1",
      adapter_key: "manual_test_adapter",
      due_at: "2026-05-25T00:00:00Z",
    });
    const created = {
      id: "task_2",
      finding_id: createTaskBody.finding_id,
      adapter_id: null,
      adapter_key: createTaskBody.adapter_key,
      assigned_user_id: null,
      status: "open",
      due_at: createTaskBody.due_at,
      completed_at: null,
      result_summary: null,
      metadata: {},
      created_at: "2026-05-13T01:00:00Z",
      updated_at: "2026-05-13T01:00:00Z",
    };
    taskItems.unshift(created);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ id: "task_2", status: "open", created_at: "2026-05-13T01:00:00Z" }),
    });
  });

  await page.route("**/v1/tasks/task_2", async (route) => {
    if (route.request().method() !== "PATCH") return route.fallback();
    updateTaskBody = JSON.parse(route.request().postData() || "{}");
    expect(updateTaskBody).toEqual({
      status: "in_progress",
      due_at: "2026-05-26T00:00:00Z",
      result_summary: "working",
      assigned_user_id: "11111111-1111-1111-1111-111111111111",
    });
    const item = taskItems.find((x) => x.id === "task_2");
    Object.assign(item, updateTaskBody, { updated_at: "2026-05-13T01:10:00Z" });
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "task_2",
        finding_id: item.finding_id,
        status: item.status,
        due_at: item.due_at,
        completed_at: null,
        result_summary: item.result_summary,
        assigned_user_id: item.assigned_user_id,
        created_at: item.created_at,
        updated_at: item.updated_at,
      }),
    });
  });

  await page.route("**/v1/tasks/task_2/queue-adapter-run", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    queueTaskBody = JSON.parse(route.request().postData() || "{}");
    expect(queueTaskBody).toEqual({
      adapter_key: "manual_test_adapter",
      action: "submit_opt_out",
    });
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        task_id: "task_2",
        adapter_run_id: "ar_1",
        job_id: "job_1",
        status: "queued",
      }),
    });
  });

  await page.route("**/v1/reminders?**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        items: reminderItems,
        next_cursor: null,
      }),
    });
  });

  await page.route("**/v1/reminders", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    createReminderBody = JSON.parse(route.request().postData() || "{}");
    expect(createReminderBody).toEqual({
      profile_id: "profile_1",
      finding_id: "finding_1",
      reminder_type: "recheck",
      next_run_at: "2026-06-15T00:00:00Z",
      interval_days: 14,
      enabled: true,
      metadata: { channel: "discord" },
    });
    const created = {
      id: "reminder_2",
      ...createReminderBody,
      created_at: "2026-05-13T02:00:00Z",
    };
    reminderItems.unshift(created);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(created),
    });
  });

  await page.route("**/v1/reminders/reminder_2", async (route) => {
    if (route.request().method() !== "PATCH") return route.fallback();
    updateReminderBody = JSON.parse(route.request().postData() || "{}");
    expect(updateReminderBody).toEqual({
      next_run_at: "2026-06-20T00:00:00Z",
      interval_days: 21,
      enabled: false,
      metadata: { channel: "email", priority: "high" },
    });
    const item = reminderItems.find((x) => x.id === "reminder_2");
    Object.assign(item, updateReminderBody);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(item),
    });
  });

  await page.goto("/ui");
  await page.fill("#email", "qa@example.com");
  await page.fill("#password", "StrongPassw0rd!123");
  await page.locator("#login-form button[type='submit']").click();

  await page.getByRole("button", { name: "Load Findings" }).click();
  await page.selectOption("#findings-select", "finding_1");

  await page.fill("#task-create-adapter-key", "manual_test_adapter");
  await page.fill("#task-create-due-at", "2026-05-25T00:00:00Z");
  await page.getByRole("button", { name: "Create Task" }).click();
  await expect(page.locator("#tasks-output")).toContainText("task_2");

  await page.selectOption("#tasks-select", "task_2");
  await page.selectOption("#task-update-status", "in_progress");
  await page.fill("#task-update-due-at", "2026-05-26T00:00:00Z");
  await page.fill("#task-update-result-summary", "working");
  await page.fill("#task-update-assigned-user-id", "11111111-1111-1111-1111-111111111111");
  await page.getByRole("button", { name: "Update Selected Task" }).click();
  await expect(page.locator("#tasks-output")).toContainText("\"in_progress\"");

  await page.getByRole("button", { name: "Queue Selected Task" }).click();
  await expect(page.locator("#tasks-output")).toContainText("job_1");

  await page.fill("#reminder-create-profile-id", "profile_1");
  await page.fill("#reminder-create-finding-id", "finding_1");
  await page.fill("#reminder-create-type", "recheck");
  await page.fill("#reminder-create-next-run-at", "2026-06-15T00:00:00Z");
  await page.fill("#reminder-create-interval-days", "14");
  await page.fill("#reminder-create-metadata", "{\"channel\":\"discord\"}");
  await page.getByRole("button", { name: "Create Reminder" }).click();
  await expect(page.locator("#reminders-output")).toContainText("reminder_2");

  await page.selectOption("#reminders-select", "reminder_2");
  await page.fill("#reminder-update-next-run-at", "2026-06-20T00:00:00Z");
  await page.fill("#reminder-update-interval-days", "21");
  await page.selectOption("#reminder-update-enabled", "false");
  await page.fill("#reminder-update-metadata", "{\"channel\":\"email\",\"priority\":\"high\"}");
  await page.getByRole("button", { name: "Update Selected Reminder" }).click();
  await expect(page.locator("#reminders-output")).toContainText("\"enabled\": false");

  expect(createTaskBody).not.toBeNull();
  expect(updateTaskBody).not.toBeNull();
  expect(queueTaskBody).not.toBeNull();
  expect(createReminderBody).not.toBeNull();
  expect(updateReminderBody).not.toBeNull();
});
