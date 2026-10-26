// Local UI behavior only. This fixture does not establish platform key storage or admission.
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { chromium } from "../../scripts/n2-ci/node_modules/playwright/index.mjs";

const origin = process.env.IDP_A04B_UI_ORIGIN ?? "http://127.0.0.1:4187";
assert.equal(new URL(origin).hostname, "127.0.0.1");
const browser = await chromium.launch({ channel: "chromium", headless: true });
const errors = [];
await mkdir("/private/tmp/idp-a04b-ui", { recursive: true });
try {
  for (const scenario of ["provision", "complete"]) {
    const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } });
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(`${origin}/embedded/registration-demo.html?scenario=${scenario}`);
    await page.getByRole("heading", { name: "登记此设备" }).waitFor();
    await page.getByLabel("设备名称").fill("Fixture device");
    await page.getByRole("button", { name: "准备登记" }).click();
    await page.getByRole("button", { name: "确认准备密钥" }).click();
    await page.getByRole("button", { name: "提交登记" }).waitFor();
    if (scenario === "complete") {
      await page.getByRole("button", { name: "提交登记" }).click();
      await page.getByText("服务端待完成", { exact: true }).waitFor();
    }
    await page.getByRole("button", { name: `模拟丢失${scenario === "provision" ? "登记提交" : "完成登记"}响应` }).click();
    if (scenario === "provision") await page.getByRole("button", { name: "提交登记" }).click();
    else await page.getByRole("button", { name: "继续完成登记" }).click();
    await page.getByText(scenario === "provision" ? "登记提交结果未确认" : "完成请求结果未确认", { exact: true }).waitFor();
    const visible = await page.locator("body").innerText();
    for (const secret of ["synthetic-grant", "test-private", "signature"]) assert.equal(visible.includes(secret), false);
    if (scenario === "provision") {
      await page.getByRole("button", { name: "延迟下一次查询并返回错误" }).click();
      await page.getByRole("button", { name: "查询登记结果" }).click();
      await page.waitForFunction(() => [...document.querySelectorAll("button")].some(button => button.textContent === "查询登记结果" && button.disabled));
      const generation = Number(await page.getByTestId("client-generation").textContent());
      await page.getByRole("button", { name: "重建客户端并恢复" }).click();
      await page.waitForFunction(old => Number(document.querySelector("[data-testid='client-generation']")?.textContent) > old, generation);
      await page.getByRole("button", { name: "释放迟到错误" }).click();
      await page.waitForFunction(() => {
        const check = [...document.querySelectorAll("button")].find(button => button.textContent === "查询登记结果");
        return !!check && !check.disabled && !document.querySelector("[role='alert']");
      });
      await page.getByText("登记提交结果未确认", { exact: true }).waitFor();
      assert.equal(await page.getByRole("alert").count(), 0, "old client error must not reach the replacement client");
      assert.equal(await page.getByRole("button", { name: "查询登记结果" }).isDisabled(), false, "old client busy state must not block the replacement client");
    }
    await page.getByRole("button", { name: "重建客户端并恢复" }).click();
    if (scenario === "provision") {
      await page.getByText("登记提交结果未确认", { exact: true }).waitFor();
      await page.getByRole("button", { name: "查询登记结果" }).click();
    } else {
      await page.getByText("完成请求结果未确认", { exact: true }).waitFor();
      await page.getByRole("button", { name: "查询登记结果" }).click();
    }
    if (scenario === "provision") {
      await page.getByText("服务端待完成", { exact: true }).waitFor();
      await page.getByRole("button", { name: "继续完成登记" }).click();
    }
    await page.getByText("登记已完成", { exact: true }).waitFor();
    assert.match(await page.locator("body").innerText(), /仍需使用此设备完成登录/);
    await page.setViewportSize({ width: 320, height: 900 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.screenshot({ path: `/private/tmp/idp-a04b-ui/${scenario}-320.png`, fullPage: true });
    assert.deepEqual(errors, []);
    await page.close();
  }
  const missing = await browser.newPage({ viewport: { width: 320, height: 800 } });
  const missingErrors = [];
  missing.on("pageerror", error => missingErrors.push(error.message));
  await missing.goto(`${origin}/embedded/registration-demo.html?scenario=missing`);
  await missing.getByText("设备登记暂不可用：宿主未提供登记客户端、持钥签名器、准入或持久存储能力。", { exact: true }).waitFor();
  assert.equal(await missing.getByRole("button", { name: "准备登记" }).count(), 0);
  assert.equal(await missing.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  assert.deepEqual(missingErrors, []);
  await missing.close();
  console.log("A04-B local registration UI recovery fixture passed");
} finally { await browser.close(); }
