import React, { StrictMode, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { DeviceScanLogin, type ScanCodeRenderer } from "./device-scan-login";
import type { DeviceScanClient } from "./device-scan-client";
import type { ScanProgress, ScanTarget } from "./scan-login-protocol";

const target: ScanTarget = { baseUrl: location.origin, tenant_id: "demo-tenant", client_id: "demo-client", entry_id: "demo-entry", device_id: "00000000-0000-4000-8000-000000000001", audience: "demo-app", verification_uri: `${location.origin}/auth/browser/device-scan/ui` };
const initial = { target, phase: "empty" as const, busy: false };
const D1 = `D1.${"A".repeat(42)}A`;
const P1 = `P1.${"A".repeat(22)}`;
function fixture() {
  let snap: any = { ...initial };
  const listeners = new Set<() => void>();
  const publish = (next: any) => { snap = { ...next }; listeners.forEach(fn => fn()); };
  let loads = 0;
  let lookups = 0;
  let loseAckReply = false;
  let loseCreateReply = false;
  let lookupReturns404 = false;
  let loseCloseReply = false;
  const progress = (state: ScanProgress["state"], delivery_state: ScanProgress["delivery_state"] = null): ScanProgress => ({
    grant_id: "00000000-0000-4000-8000-000000000002", mode: "device_display", state, version: 1, server_time_unix_secs: Math.floor(Date.now()/1000),
    expires_at_unix_secs: Math.floor(Date.now()/1000)+300, code_expires_at_unix_secs: Math.floor(Date.now()/1000)+180, approved_until_unix_secs: null,
    expires_in: 300, poll_after_ms: 0, delivery_state, issuance_operation_id: delivery_state ? "00000000-0000-4000-8000-000000000003" : null,
    recover_until_unix_secs: delivery_state ? Math.floor(Date.now()/1000)+300 : null, next_action: "status",
  });
  return {
    value: {
      target, getSnapshot: () => snap, subscribe: (fn: () => void) => { listeners.add(fn); return () => listeners.delete(fn); },
      async load() { loads++; const count = document.querySelector("[data-testid=load-count]"); if (count) count.textContent = String(loads); }, async create() { if (loseCreateReply) { loseCreateReply = false; lookupReturns404 = true; publish({ ...initial, phase: "origin-unknown", busy: false }); throw Object.assign(new Error("network_unknown"), { code: "network_unknown" }); } publish({ ...initial, phase: "waiting", progress: progress("waiting_user"), display_code: D1, verification_url: `${target.verification_uri}#code=${D1}`, busy: false }); },
      async claim(_code: string) { publish({ ...initial, phase: "waiting", progress: progress("waiting_device"), busy: false }); },
      async lookup() { lookups++; const count = document.querySelector("[data-testid=lookup-count]"); if (count) count.textContent = String(lookups); if (lookupReturns404) { lookupReturns404 = false; throw Object.assign(new Error("scan_not_found"), { code: "scan_not_found", status: 404 }); } }, async retryOrigin() { publish({ ...initial, phase: "waiting", progress: progress("waiting_user"), display_code: D1, verification_url: `${target.verification_uri}#code=${D1}`, busy: false }); }, async status() {}, async exchange() { publish({ ...snap, phase: "pending", progress: progress("issued", "recoverable"), busy: false }); },
      async recover() { if (snap.phase === "ack-unknown") publish({ ...snap, phase: "active", progress: progress("issued", "acknowledged"), busy: false, error: undefined }); }, async acknowledge() { if (loseAckReply) { loseAckReply = false; publish({ ...snap, phase: "ack-unknown", progress: progress("issued", "acknowledged"), busy: false }); throw Object.assign(new Error("network_unknown"), { code: "network_unknown" }); } publish({ ...snap, phase: "active", progress: progress("issued", "acknowledged"), busy: false }); },
      async cancel() { if (loseCloseReply) { loseCloseReply = false; publish({ ...initial, phase: "closing", busy: false }); throw Object.assign(new Error("network_unknown"), { code: "network_unknown" }); } publish({ ...initial, phase: "closed", busy: false }); }, async dispose() {},
    } as unknown as DeviceScanClient,
    approve() { if (snap.phase === "waiting") publish({ ...snap, progress: progress("approved") }); },
    loseAck() { loseAckReply = true; },
    loseCreate() { loseCreateReply = true; },
    loseClose() { loseCloseReply = true; },
    get counts() { return { loads, lookups }; },
  };
}
function App() {
  const [enabled, setEnabled] = useState(true);
  const [version, setVersion] = useState(0);
  const [clientFixture, setClientFixture] = useState(() => fixture());
  const renderer = useMemo<ScanCodeRenderer>(() => window.EmbeddedIdpScanCode ?? ({ render(el, value) { const text = document.createElementNS("http://www.w3.org/2000/svg", "text"); text.setAttribute("x", "0"); text.setAttribute("y", "20"); text.textContent = value; const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg"); svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "fixture code"); svg.append(text); el.replaceChildren(svg); }, clear(el) { el.replaceChildren(); } }), []);
  return <main style={{ maxWidth: 760, margin: "24px auto", padding: 12 }}>
    <h1>A04-D browser fixture</h1>
    <p>Only synthetic fixture values are used. Signer, transport and storage are mocked; this page does not exercise the host signer or live transport. {window.EmbeddedIdpScanCode ? "The existing scan renderer is loaded; this does not verify a physical scanner." : "Its renderer shows fixture text, not a real QR code."}</p>
    <button onClick={() => setEnabled(v => !v)}>Toggle client</button>{" "}
    <button onClick={() => clientFixture.approve()}>Simulate phone approval</button>{" "}
    <button onClick={() => clientFixture.loseAck()}>Simulate ACK reply loss</button>{" "}
    <button onClick={() => clientFixture.loseCreate()}>Simulate create reply loss</button>{" "}
    <button onClick={() => clientFixture.loseClose()}>Simulate close reply loss</button>{" "}
    <button onClick={() => { setClientFixture(fixture()); setVersion(v => v+1); }}>Reset fixture</button>
    <p data-testid="fixture-counter">{version}</p><span hidden data-testid="load-count">{clientFixture.counts.loads}</span><span hidden data-testid="lookup-count">{clientFixture.counts.lookups}</span>
    <div data-testid="scan-ui"><DeviceScanLogin key={version} client={enabled ? clientFixture.value : undefined} renderer={renderer} language="en-US" /></div>
  </main>;
}

const mount = () => createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
if (new URLSearchParams(location.search).has("real-renderer")) void import("../scan-code/main").then(mount);
else mount();
