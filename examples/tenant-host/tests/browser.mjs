import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {chromium} from '../../../scripts/n2-ci/node_modules/playwright/index.mjs';
export async function runBrowser({base,password}) {
 const browser=await chromium.launch({headless:true,...(process.platform==='darwin'?{executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'}:{})});
 const page=await browser.newPage({viewport:{width:1100,height:900}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const login=async()=>{await page.getByLabel('邮箱',{exact:true}).fill('both@example.test');await page.getByLabel('密码',{exact:true}).fill(password);await page.getByRole('button',{name:'登录',exact:true}).click();};
 const choose=async tenant=>{await page.locator('li').filter({hasText:tenant}).getByRole('button',{name:'进入',exact:true}).click();await page.getByTestId('report-panel').getByText(tenant,{exact:true}).waitFor();};
 try {
  await page.goto(base+'/fixed');await login();await page.getByRole('button',{name:'读取单份报告'}).click();await page.getByRole('heading',{name:'tenant-a report r001'}).waitFor();
  await page.reload();await page.getByTestId('report-panel').waitFor();
  await page.getByLabel('本地未保存草稿').fill('draft must survive cancellation');
  page.once('dialog',d=>d.dismiss());await page.getByRole('button',{name:'选择租户入口',exact:true}).click();assert.equal(await page.getByLabel('本地未保存草稿').inputValue(),'draft must survive cancellation');
  page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'选择租户入口',exact:true}).click();await login();await choose('tenant-b');
  await page.getByRole('button',{name:'读取单份报告'}).click();await page.getByRole('heading',{name:'tenant-b report r001'}).waitFor();
  await page.getByLabel('本地未保存草稿').fill('cancel tenant switch');page.once('dialog',d=>d.dismiss());await page.getByRole('button',{name:'切换租户',exact:true}).click();assert.equal(await page.getByLabel('本地未保存草稿').inputValue(),'cancel tenant switch');
  await page.getByLabel('本地未保存草稿').fill('');
  let release,intercepted,finished;const gate=new Promise(r=>release=r),started=new Promise(r=>intercepted=r),delivered=new Promise(r=>finished=r);
  await page.route('**/choose/api/reports/r001',async route=>{try {const response=await route.fetch();intercepted();await gate;await route.fulfill({response});} catch(error) {errors.push(error.message);} finally {finished();}});
  await page.getByRole('button',{name:'读取单份报告'}).click();await started;
  await page.getByRole('button',{name:'切换租户',exact:true}).click();await choose('tenant-a');release();await delivered;
  await page.unroute('**/choose/api/reports/r001');
  await page.getByRole('button',{name:'读取单份报告'}).click();await page.getByRole('heading',{name:'tenant-a report r001'}).waitFor();assert.equal(await page.getByRole('heading',{name:'tenant-b report r001'}).count(),0);
  await page.getByRole('button',{name:'读取已授权报告列表'}).click();await page.locator('.th-report-list').getByText('tenant-a report r001',{exact:true}).waitFor();
  await page.getByRole('button',{name:'继续读取',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('.th-report-list li').length===0 && !document.body.textContent.includes('正在读取列表'));assert.equal(await page.getByRole('button',{name:'继续读取',exact:true}).isDisabled(),true);
  await page.setViewportSize({width:320,height:900});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth),true);
  await mkdir('/private/tmp/idp-a05-ui',{recursive:true});await page.screenshot({path:'/private/tmp/idp-a05-ui/business-320.png',fullPage:true});
  await page.goto(base+'/management');await page.getByLabel('邮箱',{exact:true}).fill('admin@example.test');await page.getByLabel('密码',{exact:true}).fill(password);await page.getByRole('button',{name:'登录',exact:true}).click();
  await page.getByRole('button',{name:'打开权限目录',exact:true}).click();await page.locator('.embedded-idp-permission-directory').getByText('report::read',{exact:true}).first().waitFor();
  await page.getByRole('button',{name:'更换目标租户',exact:true}).click();await page.getByLabel('目标租户').selectOption('tenant-b');await page.getByRole('button',{name:'打开权限目录',exact:true}).click();
  await page.locator('.embedded-idp-permission-directory').getByText('report::read',{exact:true}).first().waitFor();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth),true);
  await page.screenshot({path:'/private/tmp/idp-a05-ui/management-320.png',fullPage:true});
  assert.deepEqual(errors,[]);
  console.log('A05 browser passed: Cookie reload, Fixed/Choose, draft guard, stale response isolation, reports, independent management, 320px');
 } catch (error) { console.error('Browser page at failure:', await page.locator('body').innerText()); throw error; } finally {await browser.close();}
}
