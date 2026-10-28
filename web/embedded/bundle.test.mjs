import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createElement, Fragment } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { EmbeddedAuth, EmbeddedIdentityClient, EmbeddedDeviceClient, DeviceSelfService, DeviceRegistrationClient, DeviceRegistration, buildDeviceRegistrationProofBytes, DeviceKeyRotation, DeviceKeyRotationClient, buildDeviceKeyRotationProofBytes, DeviceScanClient, DeviceScanLogin, ScanSourceEntry, buildDeviceScanProofBytes } from "@embedded-idp/react";
import { ManagementClient, PermissionDirectory } from "@embedded-idp/react/admin";
import { AccountSecurityClient, parseSecurityIntent } from "@embedded-idp/react";

test("account security SDK is exported and accepts both identity client ports", () => {
  for (const identity of [new EmbeddedIdentityClient("/idp"), new ManagementClient("/idp")]) {
    const security = new AccountSecurityClient(identity);
    const intent = security.prepareRecoveryStart("person@example.test");
    assert.equal(intent.kind, "recovery-start");
    assert.equal(intent.scope, identity.accountSecurityScope);
    assert.equal(intent.receipt_secret.length, 43);
    assert.deepEqual(parseSecurityIntent(JSON.parse(JSON.stringify(intent)), identity.accountSecurityScope), intent);
    assert.equal(typeof identity.requestAccountSecurity, "function");
    assert.equal(typeof identity.forgetAccountSecuritySession, "function");
  }
});

test("built account security SDK preserves wrong-password identity and confirms receipts after logout", async t => {
  const response = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  const calls = [];
  t.mock.method(globalThis, "fetch", async (url, init) => {
    const path = String(url);
    calls.push({ path, init });
    if (path.endsWith("/capabilities")) return response({ tenancy_enabled: false, login_tenant_policy: "fixed", fixed_tenant_id: "0" });
    if (path.endsWith("/login")) return response({ status: "authenticated",
      session: { tenant_id: "0", account_id: "fixture-account", session_id: "fixture-session", client_id: "fixture-client" },
      tokens: { access_token: "fixture-access", refresh_token: "fixture-refresh",
        access_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 3600,
        refresh_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 86400 } });
    if (path.endsWith("/security/password/result")) {
      assert.equal(init.headers.Authorization, undefined);
      assert.deepEqual(Object.keys(JSON.parse(init.body)).sort(), ["operation_id", "receipt_secret"]);
      return response({ completed: true });
    }
    if (path.endsWith("/security/password")) {
      assert.equal(init.headers.Authorization, "Bearer fixture-access");
      return JSON.parse(init.body).current_password === "incorrect"
        ? response({ code: "invalid_credentials", message: "fixed fixture error" }, 401)
        : response({ completed: true });
    }
    throw new Error("unexpected fixture request");
  });
  for (const identity of [new EmbeddedIdentityClient("/idp"), new ManagementClient("/idp")]) {
    await identity.loadCapabilities();
    await identity.login("fixture@example.test", "Fixture-password1");
    const sdk = new AccountSecurityClient(identity);
    await assert.rejects(sdk.changePassword(sdk.preparePasswordChange(), "incorrect", "New-password2"), error => error.code === "invalid_credentials");
    assert.equal(identity.getSnapshot().session.session_id, "fixture-session");
    const intent = sdk.preparePasswordChange();
    assert.deepEqual(await sdk.changePassword(intent, "Fixture-password1", "New-password2"), { completed: true });
    assert.equal(identity.getSnapshot().session, undefined);
    assert.deepEqual(await sdk.result(intent), { completed: true });
  }
  assert.equal(calls.some(call => call.path.endsWith("/refresh")), false);
});

test("embedded bundle uses host React and contains no management interface", async () => {
  const js = await readFile(new URL("./dist/embedded-idp.js", import.meta.url), "utf8");
  const css = await readFile(new URL("./dist/embedded-idp.css", import.meta.url), "utf8");
  const types = await readFile(new URL("./dist/types/index.d.ts", import.meta.url), "utf8");
  const manifest = JSON.parse(await readFile(new URL("./package.json", import.meta.url), "utf8"));
  assert.deepEqual(manifest.dependencies ?? {}, {});
  assert.deepEqual(Object.keys(manifest.peerDependencies).sort(), ["@ant-design/v5-patch-for-react-19", "antd", "react", "react-dom"]);
  assert.equal(manifest.peerDependenciesMeta.antd.optional, true);
  assert.match(js, /from\s*["']react["']/);
  assert.doesNotMatch(js, /\/admin\/|management-root|antd/);
  assert.doesNotMatch(css, /(^|})\s*(html|body|:root|\*)\s*\{/);
  assert.match(types, /EmbeddedAuth/);
  assert.ok(new EmbeddedIdentityClient("/idp"));
});

test("admin subpath exports a mountable permission directory without changing the identity entry", async () => {
  const js = await readFile(new URL("./dist/admin.js", import.meta.url), "utf8");
  const css = await readFile(new URL("./dist/admin.css", import.meta.url), "utf8");
  const types = await readFile(new URL("./dist/admin-types/embedded/admin.d.ts", import.meta.url), "utf8");
  assert.match(js, /from\s*["']antd["']/);
  assert.match(css, /embedded-idp-permission-directory/);
  assert.doesNotMatch(css, /(^|})\s*(html|body|:root|\*)\s*\{/);
  assert.match(types, /PermissionDirectory/);
  assert.ok(new ManagementClient("/idp"));
  const client = { getSnapshot: () => ({ capabilities: { tenancy_enabled: false } }) };
  const html = renderToStaticMarkup(createElement(PermissionDirectory, { client, tenant: "0" }));
  assert.match(html, /权限目录/);
});

test("two embedded forms have separate labels, language and theme roots", () => {
  const state = { selecting: false, capabilities: { tenancy_enabled: false, login_tenant_policy: "fixed", fixed_tenant_id: "0" } };
  const client = { getSnapshot: () => state, subscribe: () => () => {}, isCookieMode: () => false, isDevelopmentMode: () => false, supportsRestore: () => false };
  const html = renderToStaticMarkup(createElement(Fragment, null,
    createElement(EmbeddedAuth, { client, style: { "--embedded-idp-primary": "#2257bb" } }),
    createElement(EmbeddedAuth, { client, language: "en-US", style: { "--embedded-idp-primary": "#385542" } }),
  ));
  const labels = [...html.matchAll(/<label for="([^"]+)"/g)].map(match => match[1]);
  assert.equal(labels.length, 4);
  assert.equal(new Set(labels).size, 4);
  assert.match(html, /登录/);
  assert.match(html, /Sign in/);
  assert.match(html, /#2257bb/);
  assert.match(html, /#385542/);
});


test("device self-service is publicly mountable with independent language and theme roots", async () => {
  const identity = new EmbeddedIdentityClient("/idp");
  const client = new EmbeddedDeviceClient(identity);
  const html = renderToStaticMarkup(createElement(Fragment, null,
    createElement(DeviceSelfService, { client, style: { "--embedded-idp-primary": "#2257bb" } }),
    createElement(DeviceSelfService, { client, language: "en-US" }),
  ));
  assert.match(html, /我的设备/);
  assert.match(html, /My devices/);
  assert.match(html, /Sign in to view/);
  assert.doesNotMatch(html, /private_key|synthetic-access|解除本人绑定/);
  const types = await readFile(new URL("./dist/types/index.d.ts", import.meta.url), "utf8");
  assert.match(types, /DeviceSelfServiceProps/);
  assert.match(types, /EmbeddedDeviceClient/);
});


test("registration entry exports host contracts and is mountable without a signer", async () => {
  const html = renderToStaticMarkup(createElement(DeviceRegistration, { language: "en-US" }));
  assert.match(html, /Register this device/);
  assert.match(html, /registration is unavailable/);
  assert.doesNotMatch(html, /<button/);
  assert.equal(typeof DeviceRegistrationClient, "function");
  assert.equal(typeof buildDeviceRegistrationProofBytes, "function");
  const types = await readFile(new URL("./dist/types/index.d.ts", import.meta.url), "utf8");
  assert.match(types, /DeviceRegistrationStore/);
  assert.match(types, /DeviceRegistrationSigner/);
  const js = await readFile(new URL("./dist/embedded-idp.js", import.meta.url), "utf8");
  assert.doesNotMatch(js, /node:crypto|BEGIN PRIVATE KEY|test-candidate-one|synthetic-grant/);
});


test("rotation bundle exposes host contracts without exporting test keys", async () => {
  const html = renderToStaticMarkup(createElement(DeviceKeyRotation, { language: "en-US" }));
  assert.match(html, /rotation/i);
  assert.doesNotMatch(html, /<button/);
  assert.equal(typeof DeviceKeyRotationClient, "function");
  assert.equal(typeof buildDeviceKeyRotationProofBytes, "function");
  const types = await readFile(new URL("./dist/types/index.d.ts", import.meta.url), "utf8");
  assert.match(types, /DeviceKeyRotationSigner/);
  assert.match(types, /DeviceKeyRotationStore/);
  const js = await readFile(new URL("./dist/embedded-idp.js", import.meta.url), "utf8");
  assert.doesNotMatch(js, /synthetic-old|synthetic-new|node:crypto|BEGIN PRIVATE KEY/);
});


test("optional scan bundle exposes host contracts and safe source entry without test material", async () => {
  const html = renderToStaticMarkup(createElement(DeviceScanLogin, { language: "en-US" }));
  assert.match(html, /Scan sign-in is unavailable/);
  assert.doesNotMatch(html, /<button/);
  assert.equal(typeof DeviceScanClient, "function");
  assert.equal(typeof buildDeviceScanProofBytes, "function");
  const source = renderToStaticMarkup(createElement(ScanSourceEntry, { target: { verification_uri: "https://idp.example.test/one/auth/browser/device-scan/ui" }, language: "en-US" }));
  assert.match(source, /href="https:\/\/idp.example.test\/one\/auth\/browser\/device-scan\/ui"/);
  assert.match(source, /explicitly approve/);
  const types = await readFile(new URL("./dist/types/index.d.ts", import.meta.url), "utf8");
  for (const contract of ["DeviceScanStore", "DeviceScanSessions", "ScanSigner", "ScanCodeRenderer"]) assert.match(types, new RegExp(contract));
  const js = await readFile(new URL("./dist/embedded-idp.js", import.meta.url), "utf8");
  assert.doesNotMatch(js, /synthetic committed|node:crypto|BEGIN PRIVATE KEY/);
});

test("security UI exports default closed features and independent recovery labels", async () => {
  const { AccountSecurityPanel, PasswordRecovery, AccountSecurityWorkflow, validateAccountSecurityFeatures } = await import("@embedded-idp/react");
  const identity = new EmbeddedIdentityClient("/idp");
  const store = () => ({ read: () => null, compareAndSet: () => {} });
  assert.deepEqual(validateAccountSecurityFeatures(), { enabled: false, recovery: false });
  assert.equal(typeof AccountSecurityWorkflow, "function");
  const closed = renderToStaticMarkup(createElement(PasswordRecovery, { identity, store: store() }));
  assert.match(closed, /当前未启用密码恢复/);
  assert.doesNotMatch(closed, /type="email"/);
  const html = renderToStaticMarkup(createElement(Fragment, null,
    createElement(PasswordRecovery, { identity, features: { enabled: true, recovery: true }, store: store() }),
    createElement(PasswordRecovery, { identity, features: { enabled: true, recovery: true }, store: store(), language: "en-US" }),
  ));
  const labels = [...html.matchAll(/<label[^>]*for="([^"]+)"/g)].map(match => match[1]);
  assert.equal(labels.length, 2);
  assert.equal(new Set(labels).size, 2);
  assert.match(html, /Recover password/);
  assert.match(html, /找回密码/);
  const panel = renderToStaticMarkup(createElement(AccountSecurityPanel, { identity, store: store() }));
  assert.match(panel, /当前没有有效登录身份/);
  assert.doesNotMatch(panel, /type="password"/);
});
