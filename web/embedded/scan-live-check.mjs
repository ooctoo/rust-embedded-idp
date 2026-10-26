// Isolated reference-host check only; all keys and accounts are synthetic fixtures.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, writeFile, rename, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DeviceScanClient, buildDeviceScanProofBytes } from './dist/embedded-idp.js';
const base = process.env.IDP_A04D_BASE;
assert.ok(base?.startsWith('http://127.0.0.1:'));
const dir = await mkdtemp(join(tmpdir(), 'idp-a04d-live-'));
const privateKey = createPrivateKey({key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 0x41)]), type:'pkcs8', format:'der'});
const {crv,kty,x} = createPublicKey(privateKey).export({format:'jwk'});
const key_id = createHash('sha256').update(JSON.stringify({crv,kty,x})).digest('base64url');
const target = {baseUrl:base,tenant_id:'0',client_id:'scan-one',entry_id:'scan-one',device_id:'41414141-4141-4141-8141-414141414141',audience:'scan-one-scan',verification_uri:base+'/auth/browser/device-scan/ui'};
const signer = { async signRequest(input) { return {key_id,signature:sign(null,await buildDeviceScanProofBytes({...input,key_id}),privateKey).toString('base64url')}; } };
let cookie, expected_session;
async function browser(action, body) {
  const response = await fetch(base+'/auth/browser/'+action, {method:'POST',headers:{'Content-Type':'application/json',Origin:new URL(base).origin,'X-Embedded-Idp-Browser':'1',...(cookie?{Cookie:cookie}:{})},body:JSON.stringify(body)});
  const value = await response.json();
  assert.ok(response.ok, `source ${action}: ${response.status} ${JSON.stringify(value)}`);
  if (response.headers.getSetCookie().length) cookie=response.headers.getSetCookie().map(v=>v.split(';')[0]).join('; ');
  return value;
}
async function approve(client, mode) {
  if(mode==='create') await browser('device-scan/attach',{operation_id:randomUUID(),display_code:client.getSnapshot().display_code,expected_session});
  const grant_id=client.getSnapshot().progress.grant_id;
  const inspection=await browser('device-scan/inspect',{grant_id,expected_session});
  assert.equal(inspection.progress.state,'awaiting_approval');
  const approved=await browser('device-scan/approve',{operation_id:randomUUID(),grant_id,confirmation_revision:inspection.confirmation_revision,expected_session});
  assert.equal(approved.state,'approved');
  await client.status();
}
async function sessionStatus(bundle) { return (await fetch(base+'/auth/session',{headers:{Authorization:'Bearer '+bundle.tokens.access_token}})).status; }
let lock=Promise.resolve();
function flow(name) {
  const path=join(dir,name+'.json');
  const store={
    async withLock(_target,fn) { const previous=lock; let release; lock=new Promise(r=>{release=r;}); await previous; try{return await fn();}finally{release();} },
    async load() {try{return JSON.parse(await readFile(path,'utf8'));}catch(e){if(e.code==='ENOENT')return undefined;throw e;}},
    async save(record){await writeFile(path+'.next',JSON.stringify(record),{mode:0o600});await rename(path+'.next',path);},
  };
  let lose, beforeWrite, active=0, discarded=0;
  const counts={};
  const sessions={async activate({bundle,issuance_operation_id}){assert.equal(issuance_operation_id,(await store.load()).exchange_operation_id);assert.equal(await sessionStatus(bundle),200);active++;},async discard(){discarded++;}};
  const transport=async(url,init)=>{
    assert.equal(init.credentials,'omit');assert.equal(init.redirect,'error');assert.equal(init.cache,'no-store');
    const action=url.split('/').at(-1);
    if(url.includes('/auth/device-scan/')) {
      counts[action]=(counts[action]??0)+1;
      const record=await store.load();
      if(['create','claim'].includes(action))assert.equal(record.phase,'origin-unknown');
      if(action==='exchange')assert.equal(record.phase,'exchange-unknown');
      if(action==='acknowledge')assert.equal(record.phase,'ack-unknown');
    }
    if(action===beforeWrite){beforeWrite=undefined;throw Error('synthetic failure before send');}
    const response=await fetch(url,init);
    if(action===lose&&response.ok){lose=undefined;await response.arrayBuffer();throw Error('synthetic committed response loss');}
    if(!response.ok&&response.status!==409) console.error('device error',action,response.status,await response.clone().text());
    return response;
  };
  let current;
  return {store,counts,get active(){return active;},get discarded(){return discarded;},lose(action){lose=action;},before(action){beforeWrite=action;},client(){current?.dispose();current=new DeviceScanClient({target,signer,store,sessions,transport});return current;},dispose(){current?.dispose();}};
}
const flows=[];
try {
  const login=await browser('login',{email:'admin@example.test',password:'Runtime-Admin123'});
  expected_session=Object.fromEntries(['tenant_id','account_id','session_id','client_id'].map(k=>[k,login.session[k]]));
  await browser('device-scan/context',{expected_session});
  for(const mode of ['create','claim']) {
    const f=flow(mode);flows.push(f);let client=f.client();let code;
    if(mode==='claim')code=(await browser('device-scan/phone-codes',{operation_id:randomUUID(),entry_id:target.entry_id,expected_session})).scan_code;
    f.lose(mode);await assert.rejects(mode==='create'?client.create():client.claim(code));
    const original=await f.store.load();assert.equal(original.phase,'origin-unknown');
    client=f.client();await client.load();await client.lookup();
    assert.equal((await f.store.load()).origin_operation_id,original.origin_operation_id);
    await approve(client,mode);
    f.lose('exchange');await assert.rejects(client.exchange());assert.equal(f.active,0);
    const issuance=(await f.store.load()).exchange_operation_id;
    client=f.client();await client.load();await client.recover();
    const pending=await f.store.load();assert.equal(pending.phase,'pending');assert.equal(await sessionStatus(pending.bundle),401);assert.equal(f.active,0);
    f.lose('acknowledge');await assert.rejects(client.acknowledge());
    client=f.client();await client.load();
    // Both progress-only ACK recovery and abort-vs-ACK race must retain the original bundle.
    if(mode==='create')await client.recover();else await client.cancel();
    const active=await f.store.load();assert.equal(active.phase,'active');assert.equal(active.exchange_operation_id,issuance);assert.deepEqual(active.bundle,pending.bundle);
    assert.equal(f.active,1);assert.equal(f.discarded,0);assert.equal(f.counts[mode],1);assert.equal(f.counts.exchange,1);assert.equal(f.counts.acknowledge,1);
    client.dispose();
  }
  const cancelled=flow('close-unknown');flows.push(cancelled);let client=cancelled.client();
  cancelled.lose('create');await assert.rejects(client.create());
  cancelled.lose('close-origin');await assert.rejects(client.cancel());assert.equal((await cancelled.store.load()).phase,'closing');
  client=cancelled.client();await client.load();await client.cancel();assert.equal((await cancelled.store.load()).phase,'closed');assert.equal(cancelled.active,0);assert.equal(cancelled.discarded,1);
  const aborted=flow('pending-abort');flows.push(aborted);client=aborted.client();await client.create();await approve(client,'create');await client.exchange();
  const bundle=(await aborted.store.load()).bundle;assert.equal(await sessionStatus(bundle),401);await client.cancel();assert.equal((await aborted.store.load()).phase,'closed');assert.equal(await sessionStatus(bundle),401);assert.equal(aborted.active,0);
  // A persisted issuance ID does not prove exchange reached the server. Abort 404 must still close origin.
  const unsent=flow('unsent-exchange');flows.push(unsent);client=unsent.client();
  unsent.before('create');await assert.rejects(client.create());client=unsent.client();await client.retryOrigin();
  await approve(client,'create');unsent.before('exchange');await assert.rejects(client.exchange());
  await client.cancel();assert.equal((await unsent.store.load()).phase,'closed');assert.equal(unsent.discarded,1);assert.equal(unsent.active,0);
  console.log('A04-D real host: both modes, source approval, durable origin/exchange/ACK recovery, Pending 401, active 200, ACK/abort race and cancellation passed');
} finally {for(const f of flows)f.dispose();await rm(dir,{recursive:true,force:true});}
