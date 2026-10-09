import "@ant-design/v5-patch-for-react-19";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ManagementApp } from "./app";
import { ManagementClient } from "./client";
import { validateBrowserClientConfig } from "../embedded/browser-session";

// Host-owned, same-origin outer prefix; never a tenant ID or authentication secret.
const basePath = document.querySelector<HTMLMetaElement>('meta[name="idp-api-base"]')?.content ?? "/api";
const rawBrowserConfig = document.querySelector<HTMLMetaElement>('meta[name="idp-browser-config"]')?.content;
const browserConfig = rawBrowserConfig === undefined ? undefined : validateBrowserClientConfig(JSON.parse(rawBrowserConfig));
const client = new ManagementClient(basePath, { mode: browserConfig?.mode ?? "cookie", browserConfig });
createRoot(document.getElementById("root")!).render(<StrictMode><ManagementApp client={client} /></StrictMode>);
