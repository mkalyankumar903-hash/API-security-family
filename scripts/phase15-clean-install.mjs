/** Clean archive extraction + npm ci --omit=dev and real built-JS process invocation, no tsx. */
import {mkdtempSync,rmSync,readFileSync,existsSync,mkdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {spawnSync} from "node:child_process";
import assert from "node:assert/strict";
const artifactDir=resolve("build/phase15-release"),tmp=mkdtempSync(join(tmpdir(),"phase15-clean-"));
const run=(bin,args,cwd,env=process.env,timeout=120000)=>{
 const result=spawnSync(bin,args,{cwd,env,encoding:"utf8",timeout,maxBuffer:1048576});
 return result;
};
try{
 for(const name of ["service","worker"]){
  const cwd=join(tmp,name);mkdirSync(cwd,{recursive:true});
  assert.equal(run("tar",["-xzf",join(artifactDir,"api-"+name+".tar.gz")],cwd).status,0);
  assert(existsSync(join(cwd,"packages",name,"src",name==="service"?"server.js":"main.js")));
  const installed=run("npm",["ci","--omit=dev","--ignore-scripts","--no-audit","--no-fund"],cwd,process.env,180000);
  assert.equal(installed.status,0,"npm ci "+name+": "+installed.stderr?.slice(0,600));
  assert(!existsSync(join(cwd,"node_modules/tsx")),"release cannot depend on dev-only tsx");
  const entry="packages/"+name+"/src/"+(name==="service"?"server.js":"main.js");
  const result=run(process.execPath,[entry],cwd,{
   ...process.env,NODE_ENV:"production",SYNTHETIC_AUTH_ENABLED:"true",
   PHASE15_SIMULATOR_ENABLED:"true",GITHUB_ACTIONS:"true",
   DEV_TOKENS_JSON:'{"not-a-real-token":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}'
  },20000);
  assert.notEqual(result.status,0,name+" production boot cannot authorize synthetic Host");
  assert.match(result.stderr,/HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED/);
  assert(!String(result.stdout).includes("listening"));
  assert(!String(result.stderr).includes("not-a-real-token"));
  console.log("PHASE15_CLEAN_RUNTIME_INSTALL_AND_PRODUCTION_DENIAL_PASS:"+name);
 }
 const sd=join(tmp,"sdk");mkdirSync(sd,{recursive:true});
 assert.equal(run("npm",["install","--ignore-scripts","--no-audit","--no-fund","--prefix",sd,
  join(artifactDir,"sdk-private.tgz")],tmp,process.env,180000).status,0);
 const sdk=run(process.execPath,["--input-type=module","-e",
  "import {V13Client} from '@lumicsec/api-family-v13-sdk';if(typeof V13Client!=='function')process.exit(2)"],sd);
 assert.equal(sdk.status,0,"SDK clean ESM import: "+sdk.stderr);
 console.log("PHASE15_CLEAN_SDK_INSTALL_PASS");
 const ud=join(tmp,"ui");mkdirSync(ud,{recursive:true});
 const uiInstall=run("npm",["install","--ignore-scripts","--no-audit","--no-fund","--prefix",ud,
  join(artifactDir,"ui-private.tgz"),"react@19.1.1","react-dom@19.1.1"],tmp,process.env,180000);
 assert.equal(uiInstall.status,0,"UI clean npm install: "+uiInstall.stderr);
 const ui=run(process.execPath,["--input-type=module","-e",
  "import {Phase15Mount} from '@lumicsec/api-family-ui-rc';if(typeof Phase15Mount!=='function')process.exit(2)"],ud);
 assert.equal(ui.status,0,"UI clean ESM import: "+ui.stderr);
 console.log("PHASE15_CLEAN_UI_INSTALL_PASS");
}finally{rmSync(tmp,{recursive:true,force:true});}
