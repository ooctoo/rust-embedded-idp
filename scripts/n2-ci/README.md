# Shared Playwright test tools

This directory retains the locked Playwright dependency used by the ordinary
critical browser E2E entrypoint. The former N2 workflow and its suite driver
have been retired; this package name remains unchanged to avoid unnecessary
lockfile churn.

Install the pinned tools with Node 22.23.4 / pnpm 10.30.1:

```bash
pnpm --dir scripts/n2-ci install --frozen-lockfile --ignore-scripts --config.engine-strict=true
pnpm --dir scripts/n2-ci exec playwright install --with-deps --no-shell chromium
```

The package directly depends on Playwright 1.64.1 and its lockfile pins the
matching `playwright-core`. Browser version changes require a reviewed
package/lock change. This directory contains test tooling only and adds no
product dependency.

The E2E runner owns its isolated fixture and cleanup. It uploads only the
sanitized result whitelist; raw traces, database dumps and fixture credentials
are not routine artifacts. See the [CI design](../../docs/ci-quality-design.md),
[coverage map](../../docs/ci-quality-coverage.md), and
[N2 retirement mapping](../../docs/n2-retirement-plan-and-mapping.md).
