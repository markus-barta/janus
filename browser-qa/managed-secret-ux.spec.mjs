import { randomBytes } from "node:crypto";
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

function runtimeCanary(label) {
  return `janus-${label}-${randomBytes(24).toString("hex")}`;
}

async function expectCanariesAbsent(page, canaries) {
  const surface = await page.evaluate(() => ({
    url: window.location.href,
    html: document.documentElement.outerHTML,
    accessibility: document.querySelector("main")?.innerText ?? "",
    localStorage: { ...window.localStorage },
    sessionStorage: { ...window.sessionStorage },
    historyState: window.history.state,
  }));
  const cookies = await page.context().cookies();
  const encoded = JSON.stringify({ surface, cookies });
  for (const canary of canaries) {
    expect(encoded.includes(canary)).toBe(false);
  }
}

async function submitImportedValue(page, canary) {
  await page
    .locator('form[action="/managed-service/setup/execute"]')
    .evaluate((form, value) => {
      const input = form.querySelector('input[name="secret_value"]');
      if (!(input instanceof HTMLInputElement)) {
        throw new Error("managed secret input unavailable");
      }
      input.value = value;
      try {
        form.requestSubmit();
      } finally {
        // Keep a later Playwright failure from retaining the runtime canary in
        // its automatic accessibility/error context.
        input.value = "";
      }
    }, canary);
}

test("passwordless import forgets the value across back, refresh, and duplicate submit", async ({
  page,
}) => {
  const messages = [];
  page.on("console", (message) => messages.push(message.text()));
  page.on("pageerror", (error) => messages.push(error.message));

  await page.goto("/__managed-browser/session?kind=create");
  await expect(
    page.getByRole("heading", { name: "Add service secret" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expect(page.getByText("Reveal", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Copy", { exact: true })).toHaveCount(0);

  await page
    .getByRole("radio", { name: /Paste a value I already have/ })
    .check();
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect(
    page.getByRole("heading", { name: "Enter the value once" }),
  ).toBeVisible();

  const canary = runtimeCanary("import");
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter(({ impact }) =>
      ["serious", "critical"].includes(impact),
    ),
  ).toEqual([]);

  await submitImportedValue(page, canary);
  await expect(
    page.getByRole("heading", { name: "Operation registered" }),
  ).toBeVisible();
  await expectCanariesAbsent(page, [canary]);
  expect((await page.locator("main").ariaSnapshot()).includes(canary)).toBe(
    false,
  );

  const evidence = await (
    await page.request.get("/__managed-browser/evidence")
  ).text();
  expect(evidence.includes(canary)).toBe(false);
  expect(JSON.parse(evidence)).toMatchObject({
    executions: 1,
    last_value_byte_count: canary.length,
    authority_kind: "test_fixture",
  });

  await page.goBack();
  await expect(
    page.getByRole("button", { name: "Continue with passkey" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expectCanariesAbsent(page, [canary]);
  await page.reload();
  await expectCanariesAbsent(page, [canary]);

  await page
    .getByRole("radio", { name: /Paste a value I already have/ })
    .check();
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  const replayCanary = runtimeCanary("replay");
  await submitImportedValue(page, replayCanary);
  await expect(page.getByText("Start again from Pharos")).toBeVisible();
  await expectCanariesAbsent(page, [canary, replayCanary]);
  expect(
    messages.some((message) =>
      [canary, replayCanary].some((value) => message.includes(value)),
    ),
  ).toBe(false);
});

test("expired step-up and logout never preserve a value field", async ({
  page,
}) => {
  await page.goto("/__managed-browser/expired");
  await expect(
    page.getByRole("button", { name: "Continue with passkey" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);

  await page
    .getByRole("radio", { name: /Paste a value I already have/ })
    .check();
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect(page.locator('input[name="secret_value"]')).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByText("Continue with Zitadel")).toBeVisible();
  await page.goto(
    "/managed-service/setup?intent=intent_0123456789abcdef",
  );
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
});

test("reviewed removal stays value-free and explains the recovery boundary", async ({
  page,
}) => {
  await page.goto("/__managed-browser/session?kind=remove");
  await expect(
    page.getByRole("heading", { name: "Remove service secret" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expect(page.getByText("The secret is never revealed.")).toBeVisible();
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect(
    page.getByRole("heading", { name: "Ready to remove" }),
  ).toBeVisible();
  await expect(page.getByText("Recovery window: 24 hours")).toBeVisible();
  await expect(page.getByText("Reveal", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Copy", { exact: true })).toHaveCount(0);
  await page
    .getByRole("button", { name: "Remove secret safely" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Operation registered" }),
  ).toBeVisible();
});
