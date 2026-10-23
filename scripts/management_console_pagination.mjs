import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";

const TENANT = "tenant-a";
const DEVICE_CLIENT = "management-ui-b";

const jsonRequest = async (test, method, path, data, target) => {
  const headers = { authorization: test.bearer() };
  if (target) headers["x-embedded-idp-tenant-id"] = target;
  const response = await test.page.request.fetch(`${test.host.origin}${test.host.mount}/admin${path}`, {
    method, headers, ...(data === undefined ? {} : { data }),
  });
  assert.ok(response.ok(), `${method} ${path.split("?")[0]} returned ${response.status()}`);
  return response.json();
};

const rowKeys = page => page.locator("tbody tr[data-row-key]").evaluateAll(rows => rows.map(row => row.getAttribute("data-row-key")));

const listResponse = async (test, endpoint, target, action) => {
  const responsePromise = test.page.waitForResponse(response => {
    const url = new URL(response.url());
    return response.request().method() === "GET" && url.pathname === `${test.host.mount}${endpoint}`;
  });
  const [response] = await Promise.all([responsePromise, action()]);
  assert.ok(response.ok(), `${endpoint} returned ${response.status()}`);
  const body = await response.json();
  assert.ok(body && Array.isArray(body.items), `${endpoint} did not return a page`);
  if (target) assert.equal(response.request().headers()["x-embedded-idp-tenant-id"], target);
  else assert.equal(response.request().headers()["x-embedded-idp-tenant-id"], undefined);
  return { response, body };
};

function seedDevices(fixture, groups) {
  const schema = fixture.schemas.enabled;
  assert.match(schema, /^uib_enabled_[a-f0-9]+$/);
  assert.match(fixture.container, /^idp-ui-b-[a-f0-9]+$/);
  const now = Math.floor(Date.now() / 1000);
  const values = groups.flatMap(({ ids, status, registeredAt = now }) => ids.map((id, index) =>
    `('tenant-a','${id}','${DEVICE_CLIENT}','UIF page ${status} device ${index}','${status}',1,${registeredAt})`)).join(",\n");
  const statement = `insert into ${schema}.devices(tenant_id,id,client_id,device_name,status,version,registered_at_epoch) values\n${values};`;
  execFileSync("docker", ["exec", "-i", fixture.container, "psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-U", "uib", "-d", "uib"], {
    input: statement,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
  });
}

async function prepareFixtures(fixture, test) {
  const nonce = randomBytes(6).toString("hex");
  const existing = await jsonRequest(test, "GET", "/accounts?email=tenant-a%40example.test&limit=50", undefined, TENANT);
  assert.ok(existing.items?.length, "tenant-a must have an existing member");
  const administrator = existing.items.find(item => item.email === "tenant-a@example.test") ?? existing.items[0];
  assert.match(administrator.account_id, /^[0-9a-f-]{36}$/);

  const tenantIds = [];
  for (let index = 0; index < 51; index++) {
    const tenantId = `uif-page-${nonce}-${index}`;
    const created = await jsonRequest(test, "POST", "/tenants", {
      tenant_id: tenantId,
      name: `UIF page tenant ${nonce} ${index}`,
      allow_registration: false,
      administrator: { kind: "existing", subject_id: administrator.account_id },
    });
    assert.equal(created.tenant.tenant_id, tenantId);
    tenantIds.push(tenantId);
  }

  const accountEmails = [];
  for (let index = 0; index < 51; index++) {
    const email = `uif-page-${nonce}-${index}@example.test`;
    const created = await jsonRequest(test, "POST", "/platform/accounts", {
      tenant_id: TENANT,
      email,
      password: fixture.password,
    });
    assert.match(created.account.account_id, /^[0-9a-f-]{36}$/);
    accountEmails.push(email);
  }

  const deviceIds = Array.from({ length: 51 }, () => randomUUID());
  const excludedDeviceIds = [randomUUID(), randomUUID()];
  const now = Math.floor(Date.now() / 1000);
  seedDevices(fixture, [
    { ids: deviceIds, status: "pending" },
    // Keep the contrasting statuses just outside the newest page while making
    // them available as real exclusion controls for the status filter.
    { ids: [excludedDeviceIds[0]], status: "active", registeredAt: now + 100 },
    { ids: [excludedDeviceIds[1]], status: "disabled", registeredAt: now + 99 },
  ]);
  return {
    tenantIds,
    accountEmails,
    deviceIds,
    excludedDevices: [{ device_id: excludedDeviceIds[0], status: "active" }, { device_id: excludedDeviceIds[1], status: "disabled" }],
    filterEmail: accountEmails.at(-1),
  };
}

async function checkCursorPage({ test, hash, endpoint, target, page, button, settle, goto, filter, activate, assertFirstBody }) {
  const first = await listResponse(test, endpoint, target, async () => {
    await goto(test.page, hash);
    if (activate) await button(page, "查询").click();
  });
  assert.equal(first.body.items.length, 50, `${hash} first page must contain 50 records`);
  assert.equal(first.body.has_more, true);
  assert.equal(typeof first.body.next_cursor, "string");
  assertFirstBody?.(first.body);
  await settle(page);
  const firstKeys = await rowKeys(page);
  assert.deepEqual(firstKeys, first.body.items.map(item => itemKey(item)));

  const second = await listResponse(test, endpoint, target, () => button(page, "下一页").click());
  await settle(page);
  const secondUrl = new URL(second.response.url());
  assert.equal(secondUrl.searchParams.get("cursor"), first.body.next_cursor);
  assert.deepEqual(await rowKeys(page), second.body.items.map(item => itemKey(item)));

  const previous = await listResponse(test, endpoint, target, () => button(page, "上一页").click());
  await settle(page);
  assert.equal(new URL(previous.response.url()).searchParams.has("cursor"), false);
  assert.deepEqual(previous.body.items.map(item => itemKey(item)), first.body.items.map(item => itemKey(item)));
  assert.deepEqual(await rowKeys(page), firstKeys);

  if (filter) {
    await listResponse(test, endpoint, target, () => button(page, "下一页").click());
    await settle(page);
    const filtered = await listResponse(test, endpoint, target, filter.action(page));
    await settle(page);
    const filteredUrl = new URL(filtered.response.url());
    assert.equal(filteredUrl.searchParams.has("cursor"), false);
    for (const [key, value] of Object.entries(filter.query)) assert.equal(filteredUrl.searchParams.get(key), value, `${hash} filter query ${key}`);
    assert.equal(new URL(page.url()).search, "");
    assert.equal(new URL(page.url()).hash, hash);
    assert.ok(filtered.body.items.length > 0);
    filter.assertBody(filtered.body);
    assert.deepEqual(await rowKeys(page), filtered.body.items.map(item => itemKey(item)));
    if (filter.collectPages) {
      const allItems = [...filtered.body.items];
      let current = filtered;
      while (current.body.has_more) {
        const next = await listResponse(test, endpoint, target, () => button(page, "下一页").click());
        assert.equal(new URL(next.response.url()).searchParams.get("cursor"), current.body.next_cursor);
        allItems.push(...next.body.items);
        current = next;
      }
      filter.assertAll(allItems);
    }
  }
  await settle(page);
}

const itemKey = item => item.device_id ?? item.account_id ?? item.tenant_id;

/**
 * Real cursor pagination checks for tenants, accounts, members and devices.
 * The caller owns browser/fixture setup and passes the repository helpers.
 */
export async function runPaginationChecks({ fixture, open, goto, settle, button, pass }) {
  assert.ok(fixture?.password);
  assert.equal(typeof open, "function");
  assert.equal(typeof goto, "function");
  assert.equal(typeof settle, "function");
  assert.equal(typeof button, "function");
  assert.equal(typeof pass, "function");

  const setup = await open("enabled", "#/platform/home");
  const fixtures = await prepareFixtures(fixture, setup);
  await setup.context.close();
  pass("real tenant, account and mixed-status device pagination fixtures created in the owned schema");

  const cases = [
    {
      name: "tenants",
      hash: "#/platform/tenants",
      endpoint: "/admin/tenants",
      target: undefined,
      assertFirstBody: body => assert.ok(body.items.some(item => item.tenant_id !== fixtures.tenantIds.at(-1)), "tenant first page needs a non-target comparison"),
      filter: {
        query: { tenant_id: fixtures.tenantIds.at(-1) },
        action: page => async () => {
        await page.getByLabel("租户 ID", { exact: true }).fill(fixtures.tenantIds.at(-1));
        await button(page, "查询").click();
        },
        assertBody: body => {
          assert.equal(body.items.length, 1);
          assert.equal(body.has_more, false);
          assert.equal(body.items[0].tenant_id, fixtures.tenantIds.at(-1));
          assert.ok(body.items.every(item => item.tenant_id === fixtures.tenantIds.at(-1)));
        },
      },
    },
    {
      name: "accounts",
      hash: "#/platform/accounts",
      endpoint: "/admin/platform/accounts",
      target: undefined,
      activate: true,
      assertFirstBody: body => assert.ok(body.items.some(item => item.email !== fixtures.filterEmail), "account first page needs a non-target comparison"),
      filter: {
        query: { email: fixtures.filterEmail },
        action: page => async () => {
        await page.getByLabel("邮箱", { exact: true }).fill(fixtures.filterEmail);
        await button(page, "查询").click();
        },
        assertBody: body => {
          assert.equal(body.items.length, 1);
          assert.equal(body.has_more, false);
          assert.equal(body.items[0].email, fixtures.filterEmail);
          assert.ok(body.items.every(item => item.email === fixtures.filterEmail));
        },
      },
    },
    {
      name: "members",
      hash: "#/tenants/tenant-a/members",
      endpoint: "/admin/accounts",
      target: TENANT,
      assertFirstBody: body => assert.ok(body.items.some(item => item.email !== fixtures.filterEmail), "member first page needs a non-target comparison"),
      filter: {
        query: { email: fixtures.filterEmail },
        action: page => async () => {
        await page.getByLabel("邮箱", { exact: true }).fill(fixtures.filterEmail);
        await button(page, "查询").click();
        },
        assertBody: body => {
          assert.equal(body.items.length, 1);
          assert.equal(body.has_more, false);
          assert.equal(body.items[0].email, fixtures.filterEmail);
          assert.ok(body.items.every(item => item.email === fixtures.filterEmail));
        },
      },
    },
    {
      name: "devices",
      hash: "#/tenants/tenant-a/devices",
      endpoint: "/admin/devices",
      target: TENANT,
      assertFirstBody: body => {
        for (const excluded of fixtures.excludedDevices) assert.ok(body.items.some(item => item.device_id === excluded.device_id));
      },
      filter: {
        query: { status: "pending" },
        action: page => async () => {
        // The current device contract has no device-name filter; use the real
        // status label exposed by DeviceManagement instead of inventing one.
        await page.getByLabel("状态", { exact: true }).click();
        await page.locator(".ant-select-dropdown:visible").getByText("待登记", { exact: true }).click();
        await button(page, "查询").click();
        },
        assertBody: body => {
          assert.equal(body.items.length, 50);
          assert.equal(body.has_more, true);
          assert.equal(typeof body.next_cursor, "string");
          assert.ok(body.items.every(item => item.status === "pending"));
          for (const excluded of fixtures.excludedDevices) {
            assert.equal(body.items.some(item => item.device_id === excluded.device_id), false);
            assert.equal(excluded.status === "pending", false);
          }
          assert.deepEqual(new Set(body.items.map(item => item.device_id)).size, body.items.length);
        },
        collectPages: true,
        assertAll: items => {
          assert.equal(items.length, fixtures.deviceIds.length);
          assert.deepEqual(new Set(items.map(item => item.device_id)), new Set(fixtures.deviceIds));
          assert.ok(items.every(item => item.status === "pending"));
        },
      },
    },
  ];

  for (const item of cases) {
    const test = await open("enabled", "#/platform/home");
    try {
      await checkCursorPage({ test, hash: item.hash, endpoint: item.endpoint, target: item.target, page: test.page, button, settle, goto, filter: item.filter, activate: item.activate, assertFirstBody: item.assertFirstBody });
      pass(`${item.name}: real first/next/previous cursor pages and applicable filter reset without URL state`);
    } finally {
      await test.context.close();
    }
  }
}
