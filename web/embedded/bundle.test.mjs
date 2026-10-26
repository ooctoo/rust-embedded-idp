import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createElement, Fragment } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { EmbeddedAuth, EmbeddedIdentityClient, EmbeddedDeviceClient, DeviceSelfService, DeviceRegistrationClient, DeviceRegistration, buildDeviceRegistrationProofBytes, DeviceKeyRotation, DeviceKeyRotationClient, buildDeviceKeyRotationProofBytes, DeviceScanClient, DeviceScanLogin, ScanSourceEntry, buildDeviceScanProofBytes } from "@embedded-idp/react";
import { ManagementClient, PermissionDirectory } from "@embedded-idp/react/admin";

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
