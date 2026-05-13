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

  await page.goto("/ui");

  await expect(page.getByRole("button", { name: "Login With Passkey" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Enroll Passkey" })).toBeVisible();
  await expect(page.getByRole("button", { name: "List Passkeys" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy Selected ID" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reveal Details" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete Selected Passkey" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load Audit Log" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load Profiles" })).toBeVisible();
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

  await page.getByRole("button", { name: "Clear Sensitive UI Data" }).click();
  await expect(page.locator("#api-keys-output")).toContainText("cleared");
});
