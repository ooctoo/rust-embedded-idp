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

pub(crate) fn scan_reference_ui_router(
    config: embedded_idp_axum::BrowserSessionClientConfig,
) -> Router {
    let page = PAGE.replace(
        "<!--browser-config-->",
        &crate::admin_ui::browser_config_meta(&config),
    );
    Router::new()
        .route(
            "/",
            get(move || {
                let page = page.clone();
                async move { Html(page) }
            }),
        )
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
<html lang="en"><meta charset="utf-8"><!--browser-config--><meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Device scan login reference</title>
<style>body{font:16px system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem}input,button{font:inherit;padding:.5rem;margin:.25rem 0;width:100%;box-sizing:border-box}pre{white-space:pre-wrap;background:#f4f4f4;padding:1rem}button{cursor:pointer}</style>
<h1>Device scan login reference</h1><p>This is a same-origin development reference. It renders QR and Code 128 locally; it does not validate scanner hardware.</p>
<section id="login"><h2>Business sign-in</h2><p>Use the ordinary employee business account. This page does not use an administration session.</p><input id="email" autocomplete="username" placeholder="Email"><input id="password" type="password" autocomplete="current-password" placeholder="Password"><button id="signIn">Sign in</button></section>
<section id="tenant" hidden><h2>Choose tenant</h2><p>The normal business sign-in requires a tenant choice.</p><input id="tenantId" autocomplete="off" placeholder="Tenant ID"><button id="chooseTenant">Continue</button></section>
<p id="mode"></p><pre id="identity">Business sign-in is required.</pre><button id="signOut">Sign out</button>
<section><h2>Scan a device display code</h2><input id="display" autocomplete="off" placeholder="D1.…"><button id="attach">Show device and confirm</button></section>
<section><h2>Show a phone code to a device</h2><button id="phone">Create phone display code</button><pre id="code"></pre></section>
<section id="confirm" hidden><h2>Confirm target</h2><pre id="details"></pre><button id="approve">Approve this exact device</button><button id="deny">Deny</button><button id="cancel">Cancel this authorization</button><button id="status">Refresh status</button></section><section id="pending" hidden><button id="inspect">Check the scanned target, then confirm</button><button id="pendingCancel">Cancel this authorization</button></section>
<div id="qr" aria-label="QR code"></div><div id="barcode" aria-label="Code 128 barcode"></div><pre id="result" aria-live="polite"></pre>
<script type="module">
import '/auth/browser/device-scan/ui/assets/scan-code.js';
const {EmbeddedIdentityClient,secureRandomUuid:uuid}=window.EmbeddedIdpScanCode;
const browserConfig=JSON.parse(document.querySelector('meta[name="idp-browser-config"]').content);
const client=new EmbeddedIdentityClient('/',undefined,{mode:browserConfig.mode,browserConfig});
const root='/auth/browser/device-scan', h={'content-type':'application/json','x-embedded-idp-browser':'1'};
let expected, confirmation, entryId, grantId, blocked=false;
const out=x=>document.querySelector('#result').textContent=typeof x==='string'?x:JSON.stringify(x,null,2);
function clearTarget(){confirmation=undefined;grantId=undefined;document.querySelector('#confirm').hidden=true;document.querySelector('#pending').hidden=true;for(const id of ['qr','barcode'])window.EmbeddedIdpScanCode.clear(document.querySelector('#'+id));for(const id of ['code','details'])document.querySelector('#'+id).replaceChildren();}
function requireLogin(){blocked=true;expected=undefined;clearTarget();document.querySelector('#identity').textContent='Business sign-in is required.';document.querySelector('#login').hidden=false;}
client.subscribe(()=>{const snapshot=client.getSnapshot();if(JSON.stringify(expected)!==JSON.stringify(snapshot.session)){clearTarget();expected=snapshot.session;}document.querySelector('#tenant').hidden=!snapshot.selecting;if(!snapshot.session&&!snapshot.selecting)requireLogin();});
async function post(path,body={}) {
  if(blocked||!expected)throw new Error('Business sign-in is required.');
  await client.accessToken(); // Enforces the local access deadline, without refreshing in development mode.
  const original=expected;
  const r=await fetch(root+path,{method:'POST',headers:h,credentials:'same-origin',cache:'no-store',redirect:'error',body:JSON.stringify({...body,expected_session:original})});
  const x=await r.json().catch(()=>({}));
  if(expected!==original||blocked)throw new Error('Browser session changed; sign in again.');
  if(!r.ok){if(r.status===401||x.error==='browser_session_changed')requireLogin();throw new Error(x.error||'request rejected');}
  return x;
}
async function loadContext() {
  const x=await post('/context');
  if(!expected||['tenant_id','account_id','session_id','client_id'].some(k=>x[k]!==expected[k])){requireLogin();throw new Error('Browser identity mismatch.');}
  entryId=x.entry?.entry_id;
  document.querySelector('#identity').textContent=`Current person: ${x.account_id}\nTenant: ${x.tenant_id}\nSource client: ${x.client_id}\nAllowed modes: ${(x.entry?.modes||[]).join(', ')}`;
  document.querySelector('#login').hidden=true;document.querySelector('#tenant').hidden=true;
}
async function signedIn(){expected=client.getSnapshot().session;blocked=!expected;if(expected)await loadContext();}
const act=operation=>async()=>{try{await operation()}catch(e){out(e.message)}};
document.querySelector('#mode').textContent=client.isDevelopmentMode()?'Local HTTP development login: reload or expiry requires sign-in. Use the phone system scanner to open a device link.':'Full browser session mode.';
document.querySelector('#signIn').onclick=act(async()=>{await client.login(document.querySelector('#email').value,document.querySelector('#password').value);document.querySelector('#password').value='';await signedIn()});
document.querySelector('#chooseTenant').onclick=act(async()=>{await client.selectTenant(document.querySelector('#tenantId').value);await signedIn()});
document.querySelector('#signOut').onclick=act(async()=>{await client.logout();requireLogin();out('Signed out.');});
const fragment=new URLSearchParams(location.hash.slice(1));const fragmentCode=fragment.get('code');if(fragmentCode&&fragmentCode.startsWith('D1.')){document.querySelector('#display').value=fragmentCode;history.replaceState(null,'',location.pathname+location.search);}
await client.loadCapabilities();
if(client.supportsRestore()){try{await client.restore();await signedIn()}catch{requireLogin();}}
document.querySelector('#attach').onclick=act(async()=>{confirmation=await post('/attach',{operation_id:uuid(),display_code:document.querySelector('#display').value});grantId=confirmation.progress.grant_id;show(confirmation)});
document.querySelector('#phone').onclick=act(async()=>{const x=await post('/phone-codes',{operation_id:uuid(),entry_id:entryId});grantId=x.progress.grant_id;document.querySelector('#code').textContent=`Scan code: ${x.scan_code}`;window.EmbeddedIdpScanCode.render(document.querySelector('#qr'),x.scan_code,'qr');window.EmbeddedIdpScanCode.render(document.querySelector('#barcode'),x.scan_code,'barcode');document.querySelector('#pending').hidden=false;out(x.progress)});
function show(x){document.querySelector('#confirm').hidden=false;document.querySelector('#details').textContent=JSON.stringify({current_person:x.source?.display_name||x.source?.account_id,target:x.target},null,2)}
document.querySelector('#approve').onclick=act(async()=>{out(await post('/approve',{operation_id:uuid(),grant_id:grantId,confirmation_revision:confirmation?.confirmation_revision}));clearTarget()});
for(const action of ['deny','cancel'])document.querySelector('#'+action).onclick=act(async()=>{out(await post('/'+action,{operation_id:uuid(),grant_id:grantId}));clearTarget()});
document.querySelector('#status').onclick=act(async()=>out(await post('/status',{grant_id:grantId})));
document.querySelector('#inspect').onclick=act(async()=>{confirmation=await post('/inspect',{grant_id:grantId});show(confirmation);document.querySelector('#pending').hidden=true});
document.querySelector('#pendingCancel').onclick=act(async()=>{out(await post('/cancel',{operation_id:uuid(),grant_id:grantId}));clearTarget()});
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
        let config = embedded_idp_axum::BrowserSessionHttpConfig::new(
            "http://localhost",
            "test",
            "/auth/browser",
            embedded_idp_core::AccessTokenPurpose::Business,
        )
        .unwrap()
        .client_config();
        let app = scan_reference_ui_router(config);
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
