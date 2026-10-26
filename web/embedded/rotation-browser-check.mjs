import assert from "node:assert/strict";
import { chromium } from "../../scripts/n2-ci/node_modules/playwright/index.mjs";

const origin = process.env.IDP_A04C_UI_ORIGIN ?? "http://127.0.0.1:4187";
assert.equal(new URL(origin).hostname, "127.0.0.1");
const browser = await chromium.launch({ channel: "chromium", headless: true });
const errors = [];
try {
  const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } });
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(`${origin}/embedded/rotation-demo.html?fail-load-once=1`);
  await page.getByRole("heading", { name: "轮换设备证明密钥" }).waitFor();
  await page.getByRole("alert").waitFor();
  assert.equal(await page.getByRole("button", { name: "准备候选密钥" }).count(), 0, "must not prepare before loading the journal");
  await page.getByRole("button", { name: "重试读取" }).click();
  await page.getByRole("button", { name: "准备候选密钥" }).waitFor();
  await page.getByRole("button", { name: "准备候选密钥" }).click();
  await page.getByRole("button", { name: "确认准备新密钥" }).click();
  await page.getByRole("button", { name: "双签并轮换" }).waitFor();
  await page.getByRole("button", { name: "模拟丢失轮换响应" }).click();
  await page.getByRole("button", { name: "双签并轮换" }).click();
  await page.getByRole("button", { name: "确认提交轮换" }).click();
  await page.getByText("轮换结果未确认", { exact: true }).waitFor();
  assert.equal(await page.getByTestId("remote-current-key-version").innerText(), "2", `server fixture must commit before response loss: ${await page.getByTestId("rotation-outcome").innerText()}`);
  assert.equal(await page.getByTestId("rotate-writes").innerText(), "1");
  assert.equal(await page.getByRole("button", { name: "放弃未提交候选" }).count(), 0, "unknown state cannot discard candidate");
  const before = await page.locator("body").innerText();
  for (const secret of ["fixture-token", "fixture-refresh", "PRIVATE KEY", "current_key_signature"]) assert.equal(before.includes(secret), false);
  await page.getByRole("button", { name: "重建同一身份并恢复" }).click();
  await page.waitForFunction(() => document.querySelector("[data-testid=\"generation\"]")?.getAttribute("data-generation") === "2");
  await page.getByRole("button", { name: "查询当前设备密钥" }).click();
  const recovered = await Promise.race([
    page.getByText("候选密钥已核对为当前密钥", { exact: true }).waitFor().then(() => "active"),
    page.getByRole("alert").waitFor().then(() => "alert"),
  ]);
  if (recovered !== "active") throw new Error(`rotation recovery failed: ${await page.getByRole("alert").innerText()}`);
  assert.match(await page.locator("body").innerText(), /旧密钥仍由宿主持有/);
  const activeText = await page.locator("body").innerText();
  const keyIds = [...activeText.matchAll(/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g)].map(match => match[0]);
  assert.ok(keyIds.length >= 2, "show both public old and candidate key ids");
  await page.setViewportSize({ width: 320, height: 900 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({ path: "/private/tmp/idp-a04c-ui/320.png", fullPage: true });
  await page.getByRole("button", { name: "切换身份" }).click();
  await page.waitForFunction(() => document.querySelector("[data-testid=\"generation\"]")?.getAttribute("data-generation") === "3");
  await page.getByRole("alert").waitFor();
  const otherOwnerText = await page.locator("body").innerText();
  for (const keyId of keyIds) assert.equal(otherOwnerText.includes(keyId), false, "another owner must not see the old journal");
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  assert.deepEqual(errors, []);
  await page.close();

  const missing = await browser.newPage({ viewport: { width: 320, height: 800 } });
  missing.on("pageerror", error => errors.push(error.message));
  await missing.goto(`${origin}/embedded/rotation-demo.html?missing=1`);
  await missing.getByText("密钥轮换不可用", { exact: false }).waitFor();
  assert.equal(await missing.getByRole("button", { name: "准备候选密钥" }).count(), 0);
  assert.deepEqual(errors, []);
  await missing.close();
  console.log("A04-C rotation UI recovery fixture passed");
} finally { await browser.close(); }
