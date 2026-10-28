import "@ant-design/v5-patch-for-react-19";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ManagementApp } from "./app";
import { ManagementClient } from "./client";
import { validateBrowserClientConfig } from "../embedded/browser-session";
import { validateAccountSecurityFeatures } from "../embedded/account-security-workflow";

// Host-owned, same-origin outer prefix; never a tenant ID or authentication secret.
const basePath = document.querySelector<HTMLMetaElement>('meta[name="idp-api-base"]')?.content ?? "/api";
const rawBrowserConfig = document.querySelector<HTMLMetaElement>('meta[name="idp-browser-config"]')?.content;
const browserConfig = rawBrowserConfig === undefined ? undefined : validateBrowserClientConfig(JSON.parse(rawBrowserConfig));
const client = new ManagementClient(basePath, { mode: browserConfig?.mode ?? "cookie", browserConfig });
const root = createRoot(document.getElementById("root")!);
try {
  const rawSecurity = document.querySelector<HTMLMetaElement>('meta[name="idp-account-security"]')?.content;
  const accountSecurity = validateAccountSecurityFeatures(rawSecurity === undefined ? undefined : JSON.parse(rawSecurity));
  root.render(<StrictMode><ManagementApp client={client} accountSecurity={accountSecurity} /></StrictMode>);
} catch {
  root.render(<main role="alert"><h1>管理页面配置无效</h1><p>请联系宿主管理员检查安全功能配置。</p></main>);
}
