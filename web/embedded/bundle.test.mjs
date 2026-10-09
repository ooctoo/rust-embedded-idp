import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createElement, Fragment } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { EmbeddedAuth, EmbeddedIdentityClient } from "@embedded-idp/react";
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
