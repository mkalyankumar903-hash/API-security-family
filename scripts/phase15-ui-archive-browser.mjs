import assert from "node:assert/strict";
import {mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {join,resolve} from "node:path";
import {tmpdir} from "node:os";
import {spawn,spawnSync} from "node:child_process";
import {chromium} from "@playwright/test";
/** Tests real .tgz consumer in Chromium, without real Host identity or external network access. */
if(process.env.GITHUB_ACTIONS!=="true"||process.env.NODE_ENV!=="test")
 throw new Error("PHASE15_ARCHIVED_UI_HOST_SIMULATOR_ONLY");
const tmp=mkdtempSync(join(tmpdir(),"phase15-ui-archive-"));
let server,browser;
const url="http://127.0.0.1:5179",api="https://phase15-host-simulator.invalid";
const wait=ms=>new Promise(r=>setTimeout(r,ms));
const run=(cmd,args,dir)=>{
 const x=spawnSync(cmd,args,{cwd:dir,encoding:"utf8",timeout:180000,maxBuffer:2097152});
 assert.equal(x.status,0,cmd+":"+(x.stderr||"").slice(0,1000));
};
try{
 writeFileSync(join(tmp,"package.json"),JSON.stringify({name:"phase15-private-ui-browser-test",private:true,type:"module"},null,2));
 run("npm",["install","--ignore-scripts","--no-audit","--no-fund","--prefix",tmp,
  resolve("build/phase15-release/ui-private.tgz"),"react@19.1.1","react-dom@19.1.1"],tmp);
 writeFileSync(join(tmp,"index.html"),'<html><body><div id="root"></div><script type="module" src="/main.js"></script></body></html>');
 writeFileSync(join(tmp,"main.js"),[
 'import React from "react";',
 'import {createRoot} from "react-dom/client";',
 'import {Phase15Mount,Phase15ErrorBoundary} from "@lumicsec/api-family-ui-rc";',
 'let root=createRoot(document.getElementById("root"));',
 'let tenant="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",rev=0,token="ci-synthetic-token";',
 'const tokenProvider=()=>token;',
 'const pane=document.createElement("div");document.body.prepend(pane);',
 'for(const [title,fn] of [["Switch tenant",()=>{tenant=tenant[0]==="a"?"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";rev++;}],["Rotate session",()=>rev++],["Revoke token",()=>{token="revoked";rev++;}],["Unmount remount",()=>{root.unmount();root=createRoot(document.getElementById("root"));rev++;}]]){const b=document.createElement("button");b.textContent=title;b.onclick=()=>{fn();render();};pane.append(b);}',
 'function render(){root.render(React.createElement(Phase15Mount,{apiOrigin:"https://phase15-host-simulator.invalid",tenantContext:tenant,sessionRevision:String(rev),accessToken:tokenProvider}));}',
 'render();',
 'window.phase15CrashBoundary=()=>{const Broken=()=>{throw new Error("sensitive-internal-fixture");};root.render(React.createElement(Phase15ErrorBoundary,null,React.createElement(Broken)));};'
 ].join("\n"));
 writeFileSync(join(tmp,"vite.config.mjs"),"export default {root:"+JSON.stringify(tmp)+",server:{host:'127.0.0.1',port:5179,strictPort:true}};");
 server=spawn(resolve("node_modules/.bin/vite"),[tmp,"--config",join(tmp,"vite.config.mjs"),"--host","127.0.0.1","--port","5179","--strictPort"],{
  cwd:process.cwd(),env:{...process.env},stdio:["ignore","pipe","pipe"]
 });
 for(let i=0;i<80;i++){
  try{const rr=await fetch(url,{signal:AbortSignal.timeout(300)});if(rr.ok)break;}catch{}
  if(i===79)throw new Error("PRIVATE_UI_CONSUMER_DEV_SERVER_NOT_READY");
  await wait(100);
 }
 browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:360,height:760},reducedMotion:"reduce"});
 let simulatorRequests=0;const external=[];
 page.on("request",request=>{if(!request.url().startsWith("http://127.0.0.1:")&&!request.url().startsWith(api))external.push(request.url());});
 await page.route(api+"/**",async route=>{
  simulatorRequests++;
  const endpoint=route.request().url();
  const cors={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization,content-type","Access-Control-Allow-Methods":"GET,OPTIONS"};
  if(route.request().method()==="OPTIONS")return route.fulfill({status:204,headers:cors});
  if(route.request().headers().authorization==="Bearer revoked")
   return route.fulfill({status:403,headers:cors,contentType:"application/json",body:JSON.stringify({error:"PERMISSION_DENIED"})});
  const response=endpoint.endsWith("/v13/capabilities")?
   {schemaVersion:"api-family-commercial-v13",hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",scanningAuthority:false,meterDefinitions:[]}:
   {schemaVersion:"api-family-commercial-v13",tenantContext:"ISOLATED_SYNTHETIC_ONLY",
    hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",feature:"OFFLINE_API_ASSESSMENT_COMPLETED",
    meterUnit:"offline synthetic",billable:false,monthStart:"2026-10-01",entitlement:null,
    quota:0,consumed:0,reserved:0,remaining:0,decision:"HOST_AUTHORITY_NOT_CONFIGURED"};
  return route.fulfill({status:200,headers:cors,contentType:"application/json",body:JSON.stringify(response)});
 });
 await page.goto(url);
 const mount=page.locator("[data-phase15-mount='read-only']");
 await mount.getByRole("alert").waitFor({timeout:15000});
 assert.match(await mount.getByRole("alert").textContent(),/HOST_AUTHORITY_NOT_CONFIGURED/);
 for(const name of ["Switch tenant","Rotate session","Unmount remount","Revoke token"]){
  await page.getByRole("button",{name}).click();
  await mount.getByRole("alert").waitFor({timeout:15000});
 }
 await page.evaluate(()=>{document.documentElement.dir="rtl";document.documentElement.style.fontSize="200%";});
 assert(await mount.getByRole("heading",{name:"LumicSec API Security"}).isVisible());

 await page.keyboard.press("Tab");
 const focus=await page.evaluate(()=>document.activeElement?.textContent||"");
 assert(["Switch tenant","Rotate session","Revoke token","Unmount remount"].includes(focus.trim()),"keyboard focus must remain usable");
 await page.evaluate(()=>window.phase15CrashBoundary());
 await page.locator("[data-phase15-boundary-error='true']").waitFor({timeout:5000});
 assert.match(await page.locator("[data-phase15-boundary-error='true']").textContent(),/HOST_AUTHORITY_NOT_CONFIGURED/);
 assert(!(await page.locator("[data-phase15-boundary-error='true']").textContent()).includes("sensitive-internal-fixture"));
 assert.equal(external.length,0,"browser must not contact live external hosts");
 assert(simulatorRequests>=2,"real installed bundle should exercise simulator-only HTTP boundary");
 console.log("PHASE15_CHROMIUM_ACTUAL_PRIVATE_UI_ARCHIVE_IMPORT_MOUNT_SWITCH_RTL_REVOKE_FAIL_CLOSED_PASS");
}finally{
 if(browser)await browser.close();
 if(server){server.kill("SIGTERM");await wait(250);if(server.exitCode===null)server.kill("SIGKILL");}
 rmSync(tmp,{recursive:true,force:true});
}
