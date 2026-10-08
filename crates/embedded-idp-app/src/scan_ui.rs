//! Deliberately small same-origin reference UI for the optional scan-login
//! routes. Real hosts provide their own business UI and device presentation.
use axum::{
    extract::Path,
    http::{header::CONTENT_TYPE, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};

include!(concat!(env!("OUT_DIR"), "/scan_code_assets.rs"));

pub(crate) fn scan_reference_ui_router() -> Router {
    Router::new()
        .route("/", get(|| async { Html(PAGE) }))
        .route("/assets/:asset", get(asset))
}

async fn asset(Path(asset): Path<String>) -> Response {
    if asset.contains('/') || asset.contains('\\') || asset != "scan-code.js" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some((_, bytes)) = SCAN_CODE_ASSETS.iter().find(|(name, _)| *name == asset) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = (StatusCode::OK, *bytes).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    response
}

const PAGE: &str = r#"<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Device scan login reference</title>
<style>body{font:16px system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem}input,button{font:inherit;padding:.5rem;margin:.25rem 0;width:100%;box-sizing:border-box}pre{white-space:pre-wrap;background:#f4f4f4;padding:1rem}button{cursor:pointer}</style>
<h1>Device scan login reference</h1><p>This is a same-origin development reference. It renders QR and Code 128 locally; it does not validate scanner hardware.</p>
<section id="login"><h2>Business sign-in</h2><p>Use the ordinary employee business account. This page does not use an administration session.</p><input id="email" autocomplete="username" placeholder="Email"><input id="password" type="password" autocomplete="current-password" placeholder="Password"><button id="signIn">Sign in</button></section>
<section id="tenant" hidden><h2>Choose tenant</h2><p>The normal business sign-in requires a tenant choice.</p><input id="tenantId" autocomplete="off" placeholder="Tenant ID"><button id="chooseTenant">Continue</button></section>
<pre id="identity">Restoring ordinary business session…</pre>
<section><h2>Scan a device display code</h2><input id="display" autocomplete="off" placeholder="D1.…"><button id="attach">Show device and confirm</button></section>
<section><h2>Show a phone code to a device</h2><button id="phone">Create phone display code</button><pre id="code"></pre></section>
<section id="confirm" hidden><h2>Confirm target</h2><pre id="details"></pre><button id="approve">Approve this exact device</button><button id="deny">Deny</button><button id="cancel">Cancel this authorization</button><button id="status">Refresh status</button></section><section id="pending" hidden><button id="inspect">Check the scanned target, then confirm</button><button id="pendingCancel">Cancel this authorization</button></section>
<div id="qr" aria-label="QR code"></div><div id="barcode" aria-label="Code 128 barcode"></div><pre id="result" aria-live="polite"></pre>
<script type="module" src="/auth/browser/device-scan/ui/assets/scan-code.js"></script>
<script type="module">
const root='/auth/browser/device-scan', business='/auth/browser', h={'content-type':'application/json','x-embedded-idp-browser':'1'};
let expected, confirmation, entryId, grantId, selectionTicket;
const out=x=>document.querySelector('#result').textContent=typeof x==='string'?x:JSON.stringify(x,null,2);
async function call(base,path,body={},headers={}) { const r=await fetch(base+path,{method:'POST',headers:{...h,...headers},credentials:'same-origin',body:JSON.stringify(body)}); const x=await r.json().catch(()=>({})); if(!r.ok)throw new Error(x.code||x.error||'request rejected'); return x; }
const post=(path,body={})=>call(root,path,body);
function sessionFrom(x) { const s=x.session; return s&&{tenant_id:s.tenant_id,account_id:s.account_id,session_id:s.session_id,client_id:s.client_id}; }
async function loadContext() { const x=await post('/context'); expected={tenant_id:x.tenant_id,account_id:x.account_id,session_id:x.session_id,client_id:x.client_id}; entryId=x.entry?.entry_id; document.querySelector('#identity').textContent=`Current person: ${x.account_id}\nTenant: ${x.tenant_id}\nSource client: ${x.client_id}\nAllowed modes: ${(x.entry?.modes||[]).join(', ')}`; document.querySelector('#login').hidden=true; document.querySelector('#tenant').hidden=true; }
async function restore() { try { const x=await call(business,'/restore',{}); expected=sessionFrom(x); if (!expected) throw new Error('session response missing'); await loadContext(); } catch(e) { document.querySelector('#identity').textContent='Business sign-in is required.'; out('Business sign-in is required: '+e.message); } }
document.querySelector('#signIn').onclick=async()=>{try { const x=await call(business,'/login',{email:document.querySelector('#email').value,password:document.querySelector('#password').value}); if(x.status==='tenant_selection_required'){selectionTicket=x.selection_ticket; document.querySelector('#tenant').hidden=false; return;} expected=sessionFrom(x); if(!expected)throw new Error('sign-in response missing session'); await loadContext(); }catch(e){out(e.message)}};
document.querySelector('#chooseTenant').onclick=async()=>{try{const x=await call(business,'/tenant-selection/complete',{tenant_id:document.querySelector('#tenantId').value},{authorization:`TenantSelection ${selectionTicket}`}); selectionTicket=undefined; expected=sessionFrom(x); if(!expected)throw new Error('tenant selection response missing session'); await loadContext()}catch(e){out(e.message)}};
const fragment=new URLSearchParams(location.hash.slice(1)); const fragmentCode=fragment.get('code'); if(fragmentCode&&fragmentCode.startsWith('D1.')){document.querySelector('#display').value=fragmentCode; history.replaceState(null,'',location.pathname+location.search);}
await restore();
document.querySelector('#attach').onclick=async()=>{try{confirmation=await post('/attach',{operation_id:crypto.randomUUID(),display_code:document.querySelector('#display').value,expected_session:expected}); grantId=confirmation.progress.grant_id; show(confirmation)}catch(e){out(e.message)}};
document.querySelector('#phone').onclick=async()=>{try{const x=await post('/phone-codes',{operation_id:crypto.randomUUID(),entry_id:entryId,expected_session:expected});grantId=x.progress.grant_id; document.querySelector('#code').textContent=`Scan code: ${x.scan_code}`;window.EmbeddedIdpScanCode.render(document.querySelector('#qr'),x.scan_code,'qr');window.EmbeddedIdpScanCode.render(document.querySelector('#barcode'),x.scan_code,'barcode');document.querySelector('#pending').hidden=false;out(x.progress)}catch(e){out(e.message)}};
function show(x){document.querySelector('#confirm').hidden=false;document.querySelector('#details').textContent=JSON.stringify({current_person:x.source?.display_name||x.source?.account_id,target:x.target},null,2)}
document.querySelector('#approve').onclick=async()=>{try{out(await post('/approve',{operation_id:crypto.randomUUID(),grant_id:grantId,confirmation_revision:confirmation?.confirmation_revision,expected_session:expected}));document.querySelector('#confirm').hidden=true}catch(e){out(e.message)}};
document.querySelector('#deny').onclick=async()=>{try{out(await post('/deny',{operation_id:crypto.randomUUID(),grant_id:grantId,expected_session:expected}));document.querySelector('#confirm').hidden=true}catch(e){out(e.message)}};
document.querySelector('#cancel').onclick=async()=>{try{out(await post('/cancel',{operation_id:crypto.randomUUID(),grant_id:grantId,expected_session:expected}));document.querySelector('#confirm').hidden=true}catch(e){out(e.message)}};
document.querySelector('#status').onclick=async()=>{try{out(await post('/status',{grant_id:grantId,expected_session:expected}))}catch(e){out(e.message)}};
document.querySelector('#inspect').onclick=async()=>{try{confirmation=await post('/inspect',{grant_id:grantId,expected_session:expected});show(confirmation);document.querySelector('#pending').hidden=true}catch(e){out(e.message)}};
document.querySelector('#pendingCancel').onclick=async()=>{try{out(await post('/cancel',{operation_id:crypto.randomUUID(),grant_id:grantId,expected_session:expected}));document.querySelector('#pending').hidden=true}catch(e){out(e.message)}};
</script></html>"#;

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::scan_reference_ui_router;

    #[tokio::test]
    async fn reference_ui_serves_only_its_bundled_scan_renderer() {
        let app = scan_reference_ui_router();
        let response = app
            .clone()
            .oneshot(
                Request::get("/assets/scan-code.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .oneshot(
                Request::get("/assets/../scan-code.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
