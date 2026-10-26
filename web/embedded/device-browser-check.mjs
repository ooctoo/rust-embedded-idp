// Local fixture interaction check, using the repository's existing pinned browser tools.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { chromium } from "../../scripts/n2-ci/node_modules/playwright/index.mjs";
const origin = process.env.IDP_A04_UI_ORIGIN ?? "http://127.0.0.1:4187";
assert.equal(new URL(origin).hostname, "127.0.0.1");
const output = process.env.IDP_A04_UI_OUTPUT ?? "/private/tmp/idp-a04a-ui";
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ channel: "chromium", headless: true });
const errors = [];
try {
  const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } });
  page.on("pageerror", error => errors.push(error.message));
  const button = name => page.getByRole("button", { name, exact: true });
  await page.goto(`${origin}/embedded/device-demo.html`);
  await page.getByText("我的测试终端", { exact: true }).waitFor();
  await button("查看详情").click();
  await button("查看密钥信息").click();
  await page.getByText("ed25519", { exact: true }).waitFor();
  // Resolve the old user's held response only after the new user's empty list is shown.
  await button("延迟下一次列表").click();
  await button("刷新列表").click();
  await page.getByText("正在读取设备…", { exact: true }).waitFor();
  await button("切换测试用户").click();
  await page.getByText("当前登录身份没有已绑定设备。", { exact: true }).waitFor();
  await button("释放延迟列表").click();
  await page.waitForTimeout(150);
  assert.equal(await page.getByText("我的测试终端", { exact: true }).count(), 0);
  await button("切换测试用户").click();
  await page.getByText("我的测试终端", { exact: true }).waitFor();
  // Keyboard-triggered inline confirmation, followed by a lost mutation response.
  await button("解除本人绑定").focus();
  await page.keyboard.press("Enter");
  await page.getByRole("heading", { name: "确认解除本人绑定？" }).waitFor();
  await button("确认解除").focus();
  await page.keyboard.press("Enter");
  await button("查询原操作").waitFor();
  assert.equal(await button("解除本人绑定").isDisabled(), true);
  await page.setViewportSize({ width: 320, height: 900 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({ path: `${output}/unknown-320.png`, fullPage: true });
  // Pending intent is hidden from another owner and recoverable on reauthentication.
  await button("切换测试用户").click();
  await page.getByText("当前登录身份没有已绑定设备。", { exact: true }).waitFor();
  assert.equal(await button("查询原操作").count(), 0);
  await button("切换测试用户").click();
  await button("查询原操作").waitFor();
  await button("查询原操作").click();
  await page.getByRole("heading", { name: "解绑回执已确认", exact: true }).waitFor();
  await page.getByText("当前登录身份没有已绑定设备。", { exact: true }).waitFor();
  assert.equal(await button("查询原操作").count(), 0);
  assert.equal(await page.getByRole("heading", { name: "设备: 我的测试终端" }).count(), 0);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({ path: `${output}/receipt-320.png`, fullPage: true });
  await page.goto(`${origin}/embedded/device-demo.html?disabled=1`);
  await button("查看详情").click();
  await page.getByText("设备和本人绑定均启用时才可查询密钥信息。", { exact: true }).waitFor();
  assert.equal(await button("查看密钥信息").count(), 0);
  assert.deepEqual(errors, []);
  await writeFile(`${output}/result.json`, JSON.stringify({ status: "passed", browser: browser.version(), checks: ["details/key metadata", "late response identity isolation", "keyboard confirmation", "unknown result blocks duplicate write", "owner switch and reauthentication recovery", "320px no horizontal overflow", "receipt survives list refresh"], page_errors: errors }, null, 2));
  console.log("A04-A local browser fixture passed");
} finally { await browser.close(); }
