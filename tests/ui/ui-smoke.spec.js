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

  await page.goto("/ui");

  await expect(page.getByRole("button", { name: "Login With Passkey" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Enroll Passkey" })).toBeVisible();
  await expect(page.getByRole("button", { name: "List Passkeys" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy Selected ID" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reveal Details" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete Selected Passkey" })).toBeVisible();

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
});
