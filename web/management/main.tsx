import "@ant-design/v5-patch-for-react-19";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ManagementApp } from "./app";
import { ManagementClient } from "./client";

// Host-owned, same-origin outer prefix; never a tenant ID or authentication secret.
const basePath = document.querySelector<HTMLMetaElement>('meta[name="idp-api-base"]')?.content ?? "/api";
const client = new ManagementClient(basePath, { mode: "cookie" });
createRoot(document.getElementById("root")!).render(<StrictMode><ManagementApp client={client} /></StrictMode>);
