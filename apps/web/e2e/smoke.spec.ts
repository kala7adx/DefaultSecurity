import { expect, test } from "@playwright/test";

/**
 * The Phase 0 Definition of Done in a browser: sign in (forced password change), add the
 * demo company, see 5 findings with Cyber Essentials / ISO mappings, simulate the fixes and
 * see them auto-resolve. A deep link opened while signed out lands on the finding after
 * sign-in.
 */
const email = process.env.SKYLINE_E2E_EMAIL ?? "admin@example.com";
const bootstrapPassword = process.env.SKYLINE_E2E_PASSWORD ?? "";
// Random unless given: a fixed default would leave a known admin password behind.
const newPassword = process.env.SKYLINE_E2E_NEW_PASSWORD ?? `e2e-${crypto.randomUUID()}`;

test("onboard the demo company, find, fix and auto-resolve", async ({ page }) => {
  test.skip(!bootstrapPassword, "set SKYLINE_E2E_PASSWORD to the bootstrap admin password");

  await page.goto("/");
  await expect(page).toHaveURL(/\/login\?next=/);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(bootstrapPassword);
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page).toHaveURL(/\/change-password/);
  await page.getByLabel("Current password").fill(bootstrapPassword);
  await page.getByLabel("New password (12+ characters)").fill(newPassword);
  await page.getByLabel("Confirm new password").fill(newPassword);
  await page.getByRole("button", { name: "Change password" }).click();

  await page.goto("/integrations");
  await page.getByRole("button", { name: "Add demo company" }).click();
  await expect(page.getByText("connected")).toBeVisible({ timeout: 60_000 });

  await page.goto("/findings");
  await expect(page.getByTestId("finding-row")).toHaveCount(5, { timeout: 60_000 });
  await page.getByTestId("finding-row").first().click();
  await expect(page.getByTestId("mappings")).toContainText(/ISO 27001|Cyber Essentials/);
  const deepLink = page.url();
  await page.getByRole("button", { name: "Close" }).click();

  await page.goto("/integrations");
  await page.getByRole("button", { name: "Simulate fixes" }).click();
  await page.goto("/findings?status=resolved");
  await expect(page.getByTestId("finding-row")).toHaveCount(5, { timeout: 90_000 });

  // Signed out, the deep link goes through login and lands back on the finding.
  await page.context().clearCookies();
  await page.goto(deepLink);
  await expect(page).toHaveURL(/\/login\?next=%2Ffindings%2F/);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(newPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/findings\/[0-9a-f-]+/);
  await expect(page.getByTestId("mappings")).toBeVisible();
});
