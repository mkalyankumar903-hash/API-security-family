import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {spawn} from "node:child_process";
import {readFileSync} from "node:fs";
import {Pool} from "pg";
import {migrate,withTenant,withWorkerTenant,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {processOneJob} from "../packages/worker/src/index.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SECURITY_SOURCE=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
type Response={statusCode:number;body:string;json:()=>Record<string,unknown>};
const SUPPORTED=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"];
test("Phase10 real child SIGKILL and backend disconnect: reservation, fixture, receipt and finalization are replay-safe",async()=>{
 await migrate();
 const app=await makeApp();
 const call=async(method:"GET"|"POST",url:string,data?:object,key?:string,authority=false):Promise<Response>=>
  app.inject({method,url,payload:data,headers:{
   authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{}),
   ...(authority?{"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}:{})}}) as Promise<Response>;
 const ok=(r:Response,status:number)=>assert.equal(r.statusCode,status,r.body);
 try{
  const suffix=randomUUID().slice(0,8);
  const target=await call("POST","/v1/targets",{name:"Crash "+suffix,
   baseUrl:"https://phase10-crash-"+suffix+".fixture.invalid",environment:"SYNTHETIC"});ok(target,201);
  const tid=target.json().id as string;
  const spec=await call("POST","/v2/targets/"+tid+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:SECURITY_SOURCE},"crash-spec-"+randomUUID());ok(spec,201);
  const sid=spec.json().specificationId as string;
  const normalized=await call("GET","/v2/specifications/"+sid+"/operations?limit=100");ok(normalized,200);
  const keys=SUPPORTED.map(path=>{
   const value=(normalized.json() as unknown as {method:string;path:string;key:string}[]).find(x=>x.path===path&&x.method==="GET")?.key;
   assert.ok(value,path);return value;
  });
  for(const scenario of ["before-reservation","after-reservation","after-fixture-before-receipt",
   "db-disconnect-before-receipt","after-evaluation","after-checkpoint","before-finalization","after-report"]){
   const scope=await call("POST","/v6/pt/targets/"+tid+"/scopes",{
    specificationId:sid,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
    maxEvaluations:4,ratePerMinute:4,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
   },"pt10-crash-scope-"+randomUUID());ok(scope,201);
   const scopeId=scope.json().id as string;
   ok(await call("POST","/v6/pt/scopes/"+scopeId+"/request-authorization",{}),201);
   const permit=await call("POST","/v6/pt/test-authority/scopes/"+scopeId+"/issue",{},undefined,true);ok(permit,201);
   const permitId=permit.json().id as string;
   const run=await call("POST","/v9/pt/scopes/"+scopeId+"/orchestrations",{
    policyId:"SYNTHETIC_PT_AUTHORIZATION_FOCUSED",profile:"SECURE_BASELINE"
   },"pt10-crash-run-"+randomUUID());ok(run,201);
   const jid=run.json().id as string;
   const child=spawn(process.execPath,["--import","tsx","tests/helpers/phase10-pt-process.ts",scenario],
    {stdio:["ignore","pipe","pipe","ipc"],env:process.env});
   try{
    const event=await new Promise<{kind:string;detail:string;claim:{assessment_id:string;claim_token:string;claim_generation:number}}>((resolve,reject)=>{
     const timeout=setTimeout(()=>reject(new Error("NO_DURABLE_STAGE_IPC_"+scenario)),15000);
     child.once("message",msg=>{clearTimeout(timeout);resolve(msg as {kind:string;detail:string;claim:{assessment_id:string;claim_token:string;claim_generation:number}});});
     child.once("error",reject);
     child.once("exit",code=>{clearTimeout(timeout);reject(new Error("DISPOSABLE_PT_WORKER_EXIT_"+code));});
    });
    assert.equal(event.kind,scenario);
    assert.equal(event.claim.assessment_id,jid);
    const before=await withTenant(A,async tx=>{
     const stages=await tx.query("SELECT stage_id,status FROM api_pt9_stages WHERE assessment_id=$1 ORDER BY ordinal",[jid]);
     const ledger=await tx.query("SELECT state FROM api_pt_detection_evaluations WHERE assessment_id=$1",[jid]);
     return {stages:stages.rows,ledger:ledger.rows};
    });
    if(scenario==="after-evaluation")assert.equal(before.ledger.filter(x=>x.state==="CONSUMED").length,1);
    if(scenario==="after-checkpoint"){
     assert.ok(before.ledger.filter(x=>x.state==="CONSUMED").length>=1);
     assert.equal(before.stages.find(x=>x.stage_id==="authorization")?.status,"COMPLETED");
    }
    if(scenario==="after-report"){
     assert.equal(before.ledger.filter(x=>x.state==="CONSUMED").length,4);
     assert.equal(before.stages.find(x=>x.stage_id==="finalization")?.status,"COMPLETED");
    }
    if(scenario==="before-reservation")assert.equal(before.ledger.length,0);
    if(["after-reservation","after-fixture-before-receipt","db-disconnect-before-receipt"].includes(scenario))
     assert.deepEqual(before.ledger.map(x=>x.state),["RESERVED"],
      "durable governor reservation must exist without forged receipt or consumption");
    if(scenario==="before-finalization"){
     assert.equal(before.ledger.filter(x=>x.state==="CONSUMED").length,4);
     assert.equal(before.stages.find(x=>x.stage_id==="finalization")?.status,"RUNNING");
    }
    if(scenario==="db-disconnect-before-receipt"){
     const admin=new Pool({connectionString:process.env.MIGRATION_DATABASE_URL,max:1});
     try{
      const ended=await admin.query("SELECT pg_terminate_backend($1::int) AS disconnected",[Number(event.detail)]);
      assert.equal(ended.rows[0].disconnected,true,"real worker PostgreSQL backend terminated during in-flight receipt");
     }finally{await admin.end();}
    }
    const dead=new Promise<NodeJS.Signals|null>(resolve=>child.once("exit",(_code,signal)=>resolve(signal)));
    child.kill("SIGKILL");
    assert.equal(await dead,"SIGKILL","real kernel kill, not a thrown exception");
    if(scenario!=="after-report"){
     await withWorkerTenant(A,tx=>tx.query(
      "UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[jid]));
     assert.equal(await processOneJob(),true,"new worker resumes persisted authorized state");
    }else{
     const queue=await withWorkerTenant(A,tx=>tx.query(
      "SELECT 1 FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[jid]));
     assert.equal(queue.rowCount,0,"report committed and queued acknowledgment in one transaction");
    }
    const completed=await call("GET","/v9/pt/orchestrations/"+jid);ok(completed,200);
    const uncertain=["after-reservation","after-fixture-before-receipt",
     "db-disconnect-before-receipt"].includes(scenario);
    assert.equal(completed.json().status,uncertain?"FAILED":"COMPLETED",completed.body);
    const report=await call("GET","/v9/pt/orchestrations/"+jid+"/report");
    ok(report,uncertain?409:200);
    if(!uncertain){
    assert.equal(report.json().customerNetworkRequests,0);
    assert.equal(report.json().verifiedFixed,false);
    }
    const persisted=await withTenant(A,async tx=>{
     const ledger=await tx.query("SELECT evaluation_key,state FROM api_pt_detection_evaluations WHERE assessment_id=$1 ORDER BY evaluation_key",[jid]);
     const permit=await tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[permitId]);
     const attempts=await tx.query("SELECT claim_generation,state FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[jid]);
     const reports=await tx.query("SELECT count(*)::int AS n FROM api_pt9_reports WHERE assessment_id=$1",[jid]);
     return {ledger:ledger.rows,permit:permit.rows[0],attempts:attempts.rows,reports:reports.rows[0].n};
    });
    if(uncertain){
     assert.equal(persisted.ledger.length,1,"at most one possibly invoked fixture; never replay");
     assert.equal(persisted.ledger[0].state,"UNCERTAIN","no RESERVED may become presumed successful");
     assert.equal(persisted.permit.consumed,1,"unknown reservation consumes one governor budget");
     assert.equal(persisted.permit.reserved,0,"no phantom budget reservation persists");
     assert.equal(persisted.reports,0,"UNKNOWN / UNCERTAIN forbids successful report");
     assert.deepEqual(persisted.attempts.map(x=>x.state),["LOST","FAILED"]);
    }else{
    assert.equal(persisted.ledger.length,4,"no duplicate governed fixture interaction");
    assert.ok(persisted.ledger.every(x=>x.state==="CONSUMED"));
    assert.equal(persisted.permit.consumed,4);
    assert.equal(persisted.permit.reserved,0);
    assert.deepEqual(persisted.attempts.map(x=>x.state),
     scenario==="after-report"?["COMPLETED"]:["LOST","COMPLETED"],
     "attempt finalization must be committed atomically with the report, even after SIGKILL");
    assert.equal(persisted.reports,1,"exactly one authoritative report");
    }
   }finally{if(child.exitCode===null&&!child.killed)child.kill("SIGKILL");}
  }
 }finally{await app.close();await closeDatabase();}
});
