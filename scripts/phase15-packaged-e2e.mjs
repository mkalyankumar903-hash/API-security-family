/**
 * Isolated GitHub-runner only, compiled archives, real PostgreSQL16,
 * real API and worker child processes. NEVER use customer targets.
 */
import assert from "node:assert/strict";
import {readFileSync,mkdirSync,mkdtempSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {pathToFileURL} from "node:url";
import {spawn,spawnSync} from "node:child_process";
import {createHash,randomUUID} from "node:crypto";
if(process.env.GITHUB_ACTIONS!=="true"||process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true")
 throw new Error("PHASE15_CI_ONLY_PACKAGED_E2E");
const artifactDir=resolve("build/phase15-release"),work=mkdtempSync(join(tmpdir(),"lumicsec-phase15-e2e-"));
const host="http://127.0.0.1:33919",userToken="local-test-token-alpha",foreignToken="local-test-token-beta";
const children=[];
const output=new Map();
const env={...process.env,NODE_ENV:"test",GITHUB_ACTIONS:"true",SYNTHETIC_AUTH_ENABLED:"true",
 DATABASE_URL:"postgres://api_family:api_family_dev@127.0.0.1:55432/api_family_phase15_e2e",
 WORKER_DATABASE_URL:"postgres://api_family_queue:api_family_worker_dev@127.0.0.1:55432/api_family_phase15_e2e",
 MIGRATION_DATABASE_URL:"postgres://postgres:local_admin_only@127.0.0.1:55432/api_family_phase15_e2e",
 PORT:"33919"
};
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function checked(bin,args,cwd,withEnv=env){
 const p=spawnSync(bin,args,{cwd,env:withEnv,encoding:"utf8",timeout:180000,maxBuffer:1024*1024});
 assert.equal(p.status,0,bin+" "+args[0]+" failed: "+(p.stderr||"").slice(0,1200));return p.stdout;
}
async function req(path,{token=userToken,method="GET",body}={}){
 const res=await fetch(host+path,{method,headers:{
  authorization:"Bearer "+token,"Content-Type":"application/json",
  ...(method==="POST"?{"idempotency-key":"phase15-"+randomUUID()}: {})
 },body:body===undefined?undefined:JSON.stringify(body),redirect:"error",signal:AbortSignal.timeout(7000)});
 const raw=await res.text();let json;
 try{json=JSON.parse(raw);}catch{throw new Error("NON_JSON_HTTP_RESPONSE:"+res.status);}
 return {status:res.status,data:json};
}
function start(which){
 const cwd=join(work,which),entry=which==="service"?"packages/service/src/server.js":"packages/worker/src/main.js";
 const child=spawn(process.execPath,[entry],{cwd,env,stdio:["ignore","pipe","pipe"]});
 children.push(child);output.set(child,"");
 for(const pipe of [child.stdout,child.stderr]){
  pipe.on("data",part=>output.set(child,(output.get(child)||"").slice(-1024)+part.toString().slice(-1024)));
 }
 return child;
}
async function stop(child){
 if(child.exitCode!==null||child.signalCode!==null)return;
 child.kill("SIGTERM");
 for(let i=0;i<80;i++){if(child.exitCode!==null||child.signalCode!==null)return;await wait(100);}
 child.kill("SIGKILL");
}
async function ready(){
 for(let i=0;i<100;i++){
  try{const r=await fetch(host+"/health/live",{signal:AbortSignal.timeout(500)});
   if(r.ok)return;
  }catch{}
  await wait(120);
 }
 throw new Error("PACKAGED_SERVICE_START_FAILED:"+Array.from(output.values()).join(";").slice(0,1000));
}
try{
 checked("psql",["-h","127.0.0.1","-p","55432","-U","postgres","-d","postgres",
  "-v","ON_ERROR_STOP=1","-c","CREATE DATABASE api_family_phase15_e2e;"],work,{...env,PGPASSWORD:"local_admin_only"});
 checked("psql",["-h","127.0.0.1","-p","55432","-U","postgres","-d","api_family_phase15_e2e",
  "-v","ON_ERROR_STOP=1","-c","GRANT CONNECT ON DATABASE api_family_phase15_e2e TO api_family,api_family_queue,api_family_qa_ci; GRANT USAGE,CREATE ON SCHEMA public TO api_family;"],work,{...env,PGPASSWORD:"local_admin_only"});
 for(const which of ["service","worker"]){
  const cwd=join(work,which);mkdirSync(cwd,{recursive:true});
  checked("tar",["-xzf",join(artifactDir,"api-"+which+".tar.gz")],cwd);
  checked("npm",["ci","--omit=dev","--ignore-scripts","--no-audit","--no-fund"],cwd);
 }
 checked(process.execPath,["packages/database/src/migrate.js"],join(work,"service"));
 const svc=start("service");await ready();
 assert.equal((await req("/v1/targets",{token:"wrong-token"})).status,403);
 const created=await req("/v1/targets",{method:"POST",body:{name:"Phase15 offline fixture",environment:"SYNTHETIC",baseUrl:"https://phase15.fixture.invalid"}});
 assert.equal(created.status,201,"target "+JSON.stringify(created.data).slice(0,250));
 const targetId=created.data.id;assert.match(targetId,/^[a-f0-9-]{36}$/i);
 const spec=readFileSync(resolve("fixtures/insecure.openapi.json"),"utf8");
 const uploaded=await req("/v1/targets/"+targetId+"/specifications",{method:"POST",body:{filename:"offline.json",content:spec}});
 assert.equal(uploaded.status,201,"spec "+JSON.stringify(uploaded.data).slice(0,250));
 const job=await req("/v1/targets/"+targetId+"/assessments",{method:"POST",body:{specificationId:uploaded.data.id,mode:"SPEC_ONLY"}});
 assert.equal(job.status,201,"assessment "+JSON.stringify(job.data).slice(0,250));
 const worker=start("worker");
 let state;
 for(let i=0;i<120;i++){
  state=await req("/v1/assessments/"+job.data.id);
  if(state.data.status==="COMPLETED")break;
  if(["FAILED","CANCELLED"].includes(state.data.status))throw new Error("PACKAGED_ASSESSMENT_NOT_COMPLETED:"+state.data.status);
  await wait(300);
 }
 assert.equal(state.data.status,"COMPLETED","packaged worker failed "+Array.from(output.values()).join(";").slice(0,800));
 const report=await req("/v1/assessments/"+job.data.id+"/report");
 assert.equal(report.status,200);
 assert.equal(report.data.mode,"SPEC_ONLY");
 assert.equal(report.data.coverage.runtimeValidation,false);
 const before=createHash("sha256").update(JSON.stringify(report.data)).digest("hex");
 const denied=await req("/v1/assessments/"+job.data.id+"/report",{token:foreignToken});
 assert.equal(denied.status,404);
 assert.notEqual((await req("/v1/targets/"+targetId,{token:foreignToken})).status,200);
 // Same closed artifact SDK, independently installed outside checkout workspace.
 const sd=join(work,"sdk");mkdirSync(sd,{recursive:true});
 checked("npm",["install","--prefix",sd,"--ignore-scripts","--no-audit","--no-fund",join(artifactDir,"sdk-private.tgz")],work);
 const sdkUrl=pathToFileURL(join(sd,"node_modules/@lumicsec/api-family-v13-sdk/dist/v13.js"));
 const {V13Client}=await import(sdkUrl.href);
 const client=new V13Client({baseUrl:host,accessToken:()=>userToken,timeoutMs:8000});
 const summary=await client.summary();
 assert.equal(summary.hostAuthority,"HOST_AUTHORITY_NOT_CONFIGURED");
 assert.equal(summary.billable,false);
 await stop(worker);await stop(svc);
 const restart=start("service");await ready();
 const afterReport=await req("/v1/assessments/"+job.data.id+"/report");
 assert.equal(afterReport.status,200);
 assert.equal(createHash("sha256").update(JSON.stringify(afterReport.data)).digest("hex"),before);
 assert.equal((await req("/v1/assessments/"+job.data.id+"/report",{token:foreignToken})).status,404);
 await stop(restart);
 console.log("PHASE15_CLEAN_ARCHIVE_POSTGRES16_SERVICE_WORKER_OFFLINE_SPEC_REPORT_SDK_RLS_RESTART_PASS");
}finally{
 for(const child of children)await stop(child);
 rmSync(work,{recursive:true,force:true});
}
