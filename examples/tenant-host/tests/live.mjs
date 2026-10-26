// Local disposable integration only. Requires built binary/Web and cached postgres:18.6-bookworm.
import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {createServer} from 'node:net';
const root=resolve(fileURLToPath(new URL('../../../',import.meta.url)));
const dir=await mkdtemp(join(tmpdir(),'a05-live-'));
const name='idp-a05-'+randomUUID().slice(0,8);
const password='Synthetic-A05-Only123';
let child, container=false;
const command=(cmd,args,opts={})=>{const r=spawnSync(cmd,args,{cwd:root,encoding:'utf8',...opts});if(r.status!==0)throw Error(`${cmd} failed: ${r.stderr||r.stdout}`);return r.stdout.trim();};
const delay=ms=>new Promise(r=>setTimeout(r,ms));
const port=await new Promise(resolve=>{const s=createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
const base=`http://127.0.0.1:${port}`;
let env;
const cli=(action,args=[],input)=>command(join(root,'target/debug/embedded-idp-tenant-host'),[action,...args],{env,input});
const sql=q=>command('docker',['exec','-i',name,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-At'],{input:q});
const expect=async(response,status)=>{assert.equal(response.status,status,`HTTP expected ${status}, got ${response.status} at ${new URL(response.url).pathname}`);return response;};
const req=(path,token,init={})=>fetch(base+path,{...init,headers:{...(token?{Authorization:`Bearer ${token}`} : {}),...init.headers}});
async function login(entry,email='both@example.test') {const r=await req(`/${entry}/auth/login`,null,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});await expect(r,200);return r.json();}
async function select(login,tenant) {const r=await req('/choose/auth/tenant-selection/complete',null,{method:'POST',headers:{Authorization:'TenantSelection '+login.selection_ticket,'Content-Type':'application/json'},body:JSON.stringify({tenant_id:tenant})});await expect(r,200);return r.json();}
try {
 command('docker',['run','--rm','-d','--name',name,'-e','POSTGRES_PASSWORD='+password,'-p','127.0.0.1::5432','postgres:18.6-bookworm']);container=true;
 let ready=false;for(let n=0;n<80;n++){if(spawnSync('docker',['exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],{stdio:'ignore'}).status===0){ready=true;break;}await delay(250);}assert.ok(ready,'Postgres ready');
 const pgPort=command('docker',['port',name,'5432/tcp']).split(':').at(-1);
 const key=join(dir,'key.der');command('openssl',['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',join(dir,'key.pem')]);command('openssl',['pkcs8','-topk8','-nocrypt','-in',join(dir,'key.pem'),'-outform','DER','-out',key]);command('chmod',['600',key]);
 env={...process.env,TENANT_HOST_PG_URI:`postgres://postgres:${password}@127.0.0.1:${pgPort}/postgres`,TENANT_HOST_PG_SCHEMA:'a05_identity',TENANT_HOST_BUSINESS_SCHEMA:'a05_reports',TENANT_HOST_BIND_ADDR:`127.0.0.1:${port}`,TENANT_HOST_BROWSER_ORIGIN:base,TENANT_HOST_SIGNING_KEY_FILE:key,TENANT_HOST_MANAGEMENT:'true'};
 sql('create schema a05_foreign; create schema a05_taken;');
 const rejectCli=(action,patch)=>{const r=spawnSync(join(root,'target/debug/embedded-idp-tenant-host'),[action],{env:{...env,...patch},encoding:'utf8'});assert.notEqual(r.status,0);};
 rejectCli('db-init',{TENANT_HOST_BUSINESS_SCHEMA:'a05_foreign'});
 rejectCli('db-init',{TENANT_HOST_PG_SCHEMA:'a05_taken',TENANT_HOST_BUSINESS_SCHEMA:'a05_other'});
 assert.equal(sql("select count(*) from pg_namespace where nspname in ('a05_identity','a05_reports','a05_other')"),'0');
 cli('db-init');cli('db-init');cli('bootstrap-admin',['admin@example.test'],password);cli('prepare-clients');cli('prepare-clients');
 sql("update a05_identity.oidc_clients set client_name='conflict fixture' where client_id='tenant-host-fixed'");
 rejectCli('prepare-clients',{});assert.equal(sql("select client_name from a05_identity.oidc_clients where client_id='tenant-host-fixed'"),'conflict fixture');
 sql("update a05_identity.oidc_clients set client_name='Tenant Host Fixed' where client_id='tenant-host-fixed'");
 cli('seed-fixtures',['admin@example.test'],JSON.stringify({admin_password:password,fixture_password:password}));
 let stderr='';child=spawn(join(root,'target/debug/embedded-idp-tenant-host'),['serve'],{env,cwd:root,stdio:['ignore','ignore','pipe']});child.stderr.on('data',b=>stderr+=b);
 ready=false;for(let n=0;n<120;n++){try{if((await fetch(base+'/healthz')).ok){ready=true;break;}}catch{}if(child.exitCode!==null)throw Error('host failed '+stderr);await delay(250);}assert.ok(ready,'host startup');
 const fixed=await login('fixed');assert.equal(fixed.session.tenant_id,'tenant-a');const a=fixed.tokens.access_token;
 await expect(await req('/fixed/auth/tenant-selection/tenants',a),404);
 const chosen=await login('choose');assert.equal(chosen.status,'tenant_selection_required');
 const bSession=await select(chosen,'tenant-b');const b=bSession.tokens.access_token;
 const aReport=await (await expect(await req('/fixed/api/reports/r001',a),200)).json();const bReport=await(await expect(await req('/choose/api/reports/r001',b),200)).json();assert.equal(aReport.tenant_id,'tenant-a');assert.equal(bReport.tenant_id,'tenant-b');assert.notEqual(aReport.title,bReport.title);
 await expect(await req('/choose/api/reports/r001',a),401);await expect(await req('/fixed/api/reports/r001',b),401);
 await expect(await req('/fixed/api/reports/r001',a,{headers:{'x-embedded-idp-tenant-id':'tenant-b'}}),401);
 await expect(await req('/fixed/api/reports/r002',a),403);await expect(await req('/fixed/api/reports/absent',a),403);await expect(await req('/fixed/api/reports/missing',a),404);
 const page=await(await expect(await req('/fixed/api/reports?limit=1',a),200)).json();assert.deepEqual(page.items.map(r=>r.report_id),['r001']);assert.equal(page.has_more,true);
 const next=await(await expect(await req('/fixed/api/reports?limit=1&cursor='+encodeURIComponent(page.next_cursor),a),200)).json();assert.equal(next.items.length,0);assert.equal(next.has_more,true);
 const last=await(await expect(await req('/fixed/api/reports?limit=1&cursor='+encodeURIComponent(next.next_cursor),a),200)).json();assert.deepEqual(last,{items:[],has_more:false,next_cursor:null});
 await expect(await req('/fixed/api/reports?limit=2&cursor='+encodeURIComponent(page.next_cursor),a),400);
 await expect(await req('/choose/api/reports?limit=1&cursor='+encodeURIComponent(page.next_cursor),b),400);
 await expect(await req('/fixed/api/reports?limit=1&cursor='+encodeURIComponent(page.next_cursor+'x'),a),400);
 for(const q of ['limit=0','limit=21','limit=1&limit=2','unknown=x'])await expect(await req('/fixed/api/reports?'+q,a),400);
 assert.deepEqual(await(await expect(await req('/fixed/api/reports?prefix=none',a),200)).json(),{items:[],has_more:false,next_cursor:null});
 const onlyFixed=await login('fixed','only-a@example.test');
 const onlyPage=await(await expect(await req('/fixed/api/reports?limit=1',onlyFixed.tokens.access_token),200)).json();
 await expect(await req('/fixed/api/reports?limit=1&cursor='+encodeURIComponent(page.next_cursor),onlyFixed.tokens.access_token),400);
 await expect(await req('/fixed/api/reports?limit=1&prefix=r0&cursor='+encodeURIComponent(page.next_cursor),a),400);
 const only=await login('choose','only-a@example.test');const tenants=await(await expect(await req('/choose/auth/tenant-selection/tenants',null,{headers:{Authorization:'TenantSelection '+only.selection_ticket}}),200)).json();assert.deepEqual(tenants.tenants.map(t=>t.tenant_id),['tenant-a']);
 const denied=await req('/choose/auth/tenant-selection/complete',null,{method:'POST',headers:{Authorization:'TenantSelection '+only.selection_ticket,'Content-Type':'application/json'},body:JSON.stringify({tenant_id:'tenant-b'})});assert.ok([401,403].includes(denied.status));
 const admin=await(await expect(await req('/control/admin/auth/login',null,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'admin@example.test',password})}),200)).json();
 await expect(await req('/control/admin/access/permissions',a,{headers:{'x-embedded-idp-tenant-id':'tenant-a'}}),401);
 await expect(await req('/fixed/api/reports/r001',admin.tokens.access_token),401);
 await expect(await req('/control/admin/access/permissions',admin.tokens.access_token,{headers:{'x-embedded-idp-tenant-id':'tenant-a'}}),200);
 const browserHeaders={'Content-Type':'application/json',Origin:base,'x-embedded-idp-browser':'1'};
 const cookieLogin=await expect(await req('/fixed/auth/browser/login',null,{method:'POST',headers:browserHeaders,body:JSON.stringify({email:'both@example.test',password})}),200);
 const cookie=cookieLogin.headers.getSetCookie()[0];assert.match(cookie,/Path=\/fixed\/auth\/browser/);const cookieValue=cookie.split(';')[0];const browserValue=await cookieLogin.json();
 await expect(await req('/fixed/auth/browser/restore',null,{method:'POST',headers:{...browserHeaders,Cookie:cookieValue},body:'{}'}),200);
 await expect(await req('/choose/auth/browser/restore',null,{method:'POST',headers:{...browserHeaders,Cookie:cookieValue},body:'{}'}),401);
 await expect(await req('/fixed/api/reports/r001',null,{headers:{Cookie:cookieValue}}),401);
 if(process.argv.includes('--browser')) {const {runBrowser}=await import('./browser.mjs');await runBrowser({base,password,output:dir});}
 for(const status of ['suspended','removed']) {
   sql(`update a05_identity.access_memberships set status='${status}',version=version+1,removed_at_epoch=${status==='removed'?'1':'null'} where tenant_id='tenant-b' and account_id=(select id from a05_identity.accounts where email='both@example.test');`);
   await expect(await req('/choose/api/reports/r001',b),401);
   await expect(await req('/fixed/api/reports/r001',a),200);
 }
 sql("update a05_identity.accounts set status='disabled' where email='both@example.test';");await expect(await req('/fixed/api/reports/r001',a),401);
 assert.equal((await req('/fixed/api/reports/r001',a)).headers.get('cache-control'),'no-store');
 child.kill('SIGTERM');await new Promise(r=>child.once('exit',r));
 child=spawn(join(root,'target/debug/embedded-idp-tenant-host'),['serve'],{env:{...env,TENANT_HOST_MANAGEMENT:'false'},cwd:root,stdio:'ignore'});
 ready=false;for(let n=0;n<120;n++){try{if((await fetch(base+'/healthz')).ok){ready=true;break;}}catch{}if(child.exitCode!==null)throw Error('management-disabled host failed');await delay(100);}assert.ok(ready);
 await expect(await req('/management'),404);await expect(await req('/control/admin/auth/capabilities'),404);
 assert.equal((await(await req('/example-config')).json()).management_enabled,false);
 await expect(await req('/fixed/api/reports?limit=1&cursor='+encodeURIComponent(onlyPage.next_cursor),onlyFixed.tokens.access_token),400);
 console.log('A05 live passed: Fixed/Choose, tenant isolation, membership, 403/404, bounded list/cursor, management separation, Cookie restore, revocation'+(process.argv.includes('--browser')?', browser':''));
} finally {
 if(child&&child.exitCode===null){child.kill('SIGTERM');await Promise.race([new Promise(r=>child.once('exit',r)),delay(3000)]);if(child.exitCode===null)child.kill('SIGKILL');}
 if(container)command('docker',['rm','-fv',name]);
 await rm(dir,{recursive:true,force:true});
}
