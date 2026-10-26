import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const root=new URL('../',import.meta.url);
const [raw,rust,main]=await Promise.all(['examples/tenant-host/api-contract.json','examples/tenant-host/src/reports.rs','examples/tenant-host/src/main.rs'].map(p=>readFile(new URL(p,root),'utf8')));
const contract=JSON.parse(raw);
const routes=[...rust.matchAll(/\.route\("([^"]+)",\s*get\(/g)].map(m=>m[1].replace(':id','{id}')).sort();
assert.deepEqual(contract.business_routes.map(r=>r.path.replace('/{entry}','')).sort(),routes);
assert.match(main,/for entry in \["fixed", "choose"\]/);
for(const route of contract.business_routes){assert.deepEqual(route.entries,['fixed','choose']);assert.equal(route.method,'GET');assert.equal(route.cache_control,'no-store');}
assert.match(rust,/const MAX_SCAN: usize = 40;/);assert.match(rust,/const MAX_PAGE: usize = 20;/);assert.match(rust,/const DEFAULT_PAGE: usize = 10;/);
assert.deepEqual([...rust.match(/struct ListQuery \{([\s\S]*?)\}/)[1].matchAll(/\s+(\w+):/g)].map(m=>m[1]).sort(),Object.keys(contract.business_routes.find(r=>r.request.query).request.query).sort());
assert.deepEqual([...rust.match(/pub struct Report \{([\s\S]*?)\}/)[1].matchAll(/pub (\w+):/g)].map(m=>m[1]).sort(),contract.response_fields.report.slice().sort());
assert.deepEqual([...rust.match(/struct ReportPage \{([\s\S]*?)\}/)[1].matchAll(/\s+(\w+):/g)].map(m=>m[1]).sort(),contract.response_fields.page.slice().sort());
console.log('A05 example route/query/response fields and bounds match its independent contract');
