import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {spawn} from "node:child_process";
import {processOneJob} from "../packages/worker/src/index.js";
import {migrate,pool,claimJob,renewWorkerClaim,withTenant,withWorkerTenant,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const spec=JSON.stringify({openapi:"3.1.0",info:{title:"Worker fixture",version:"1.0.0"},
 paths:{"/health":{get:{responses:{"200":{description:"Synthetic"}}}}}});

test("Phase10 PostgreSQL: atomic claims, generations, tenant read-only status and renewal",async()=>{
 await migrate();
 const app=await makeApp();
 const req=async(method:"POST"|"GET",path:string,data?:object,token="local-test-token-alpha",key?:string)=>
  app.inject({method,url:path,payload:data,headers:{authorization:"Bearer "+token,...(key?{"idempotency-key":key}:{})}});
 try{
  const migrated=await pool.query("SELECT version FROM api_schema_migrations WHERE version='014'");
  assert.equal(migrated.rowCount,1,"additive migration 014 executed");
  const rls=await pool.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname IN ('api_worker_attempts','api_worker_events','api_worker_quarantine')");
  assert.equal(rls.rowCount,3);assert.ok(rls.rows.every(x=>x.relrowsecurity&&x.relforcerowsecurity));
  const isolation=await pool.query(
   "SELECT has_column_privilege('api_family','public.api_worker_attempts','claim_token','SELECT') AS leak");
  assert.equal(isolation.rows[0].leak,false,"app role cannot read worker claim secrets");
  const fk=await pool.query(
   "SELECT pg_get_constraintdef(oid) AS rule FROM pg_constraint WHERE conname='api_worker_events_tenant_id_attempt_id_fkey'");
  assert.ok(fk.rows.some(row=>String(row.rule).includes("FOREIGN KEY (tenant_id, attempt_id)")),
   "event attribution must be tenant-bound");
  const name=randomUUID().slice(0,8);
  const t=await req("POST","/v1/targets",{name:"Worker "+name,baseUrl:"https://phase10-"+name+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(t.statusCode,201,t.body);
  const tid=t.json().id as string;
  const s=await req("POST","/v1/targets/"+tid+"/specifications",{filename:"worker.openapi.json",content:spec});
  assert.equal(s.statusCode,201,s.body);
  const sid=s.json().id as string;
  const created=await req("POST","/v1/targets/"+tid+"/assessments",{specificationId:sid,mode:"SPEC_ONLY"},"local-test-token-alpha","worker-"+randomUUID());
  assert.equal(created.statusCode,201,created.body);
  const id=created.json().id as string;
  assert.equal((await req("GET","/v10/workers/assessments/"+id+"/execution","" as unknown as object,"local-test-token-beta")).statusCode,404);
  const before=await req("GET","/v10/workers/assessments/"+id+"/execution");
  assert.equal(before.statusCode,200,before.body);
  assert.equal(before.json().schemaVersion,"pt-worker-safety-v1");
  assert.equal(before.json().queue.queueState,"QUEUED");
  await assert.rejects(()=>withTenant(A,tx=>tx.query("SELECT assessment_id FROM api_queue.api_assessment_queue LIMIT 1")),
   /permission denied/i,"application role must not read the private queue");
  const concurrent=await Promise.all([claimJob(),claimJob()]);
  const owners=concurrent.filter(x=>x?.assessment_id===id);
  assert.equal(owners.length,1,"exactly one worker claims same logical job");
  const claim=owners[0]!;
  assert.equal(claim.claim_generation,1);
  assert.equal(await renewWorkerClaim(claim),true);
  assert.equal(await renewWorkerClaim({...claim,claim_token:randomUUID()}),false);
  const after=await req("GET","/v10/workers/assessments/"+id+"/execution");
  assert.equal(after.statusCode,200,after.body);
  assert.equal(after.json().queue.claimGeneration,1);
  assert.equal(after.json().attempts.length,1);
  const forbidden=await withTenant(B,tx=>tx.query("SELECT id FROM api_worker_attempts WHERE assessment_id=$1",[id]));
  assert.equal(forbidden.rowCount,0);
  await withWorkerTenant(A,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[id]));
  assert.equal(await renewWorkerClaim(claim),false,"expired worker cannot renew");
  const taken=await claimJob();
  assert.equal(taken?.assessment_id,id,"expired worker's job is eligible for safe takeover");
  assert.equal(taken?.claim_generation,2);
  assert.notEqual(taken?.claim_token,claim.claim_token);
  assert.equal(await renewWorkerClaim(claim),false,"old generation cannot heartbeat after takeover");
  assert.equal(await renewWorkerClaim(taken!),true);
  const history=await withTenant(A,tx=>tx.query("SELECT claim_generation,state FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[id]));
  assert.deepEqual(history.rows.map(x=>[Number(x.claim_generation),x.state]),[[1,"LOST"],[2,"ACTIVE"]]);
  const tenantB=await req("GET","/v10/workers/assessments/"+id+"/execution",undefined,"local-test-token-beta");
  assert.equal(tenantB.statusCode,404);
  // Finish the takeover using the real older SPEC_ONLY worker engine.
  await withWorkerTenant(A,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[id]));
  assert.equal(await processOneJob(),true);
  const restored=await req("GET","/v1/assessments/"+id);
  assert.equal(restored.json().status,"COMPLETED",restored.body);

  // Real child process crash on a private claim and on a renewed heartbeat.
  // Parent synchronizes using IPC then sends OS SIGKILL, never a thrown mock exception.
  for(const scenario of ["claimed","heartbeat"]){
   const next=await req("POST","/v1/targets/"+tid+"/assessments",{specificationId:sid,mode:"SPEC_ONLY"},
    "local-test-token-alpha","worker-crash-"+randomUUID());
   assert.equal(next.statusCode,201,next.body);
   const crashId=next.json().id as string;
   const child=spawn(process.execPath,["--import","tsx","tests/helpers/phase10-disposable-worker.ts",scenario],
    {stdio:["ignore","pipe","pipe","ipc"],env:process.env});
   try{
    const message=await new Promise<{claim:{assessment_id:string;claim_token:string;claim_generation:number}}>((resolve,reject)=>{
     const limit=setTimeout(()=>reject(new Error("DISPOSABLE_WORKER_IPC_TIMEOUT")),12000);
     child.once("message",data=>{clearTimeout(limit);resolve(data as {claim:{assessment_id:string;claim_token:string;claim_generation:number}});});
     child.once("error",reject);
     child.once("exit",code=>{clearTimeout(limit);reject(new Error("WORKER_EXIT_BEFORE_IPC_"+code));});
    });
    assert.equal(message.claim.assessment_id,crashId,"child claimed the real seeded job");
    const exited=new Promise<{signal:NodeJS.Signals|null}>((resolve)=>child.once("exit",(_code,signal)=>resolve({signal})));
    child.kill("SIGKILL");
    assert.equal((await exited).signal,"SIGKILL");
    const previous=await withTenant(A,tx=>tx.query("SELECT state FROM api_worker_attempts WHERE assessment_id=$1",[crashId]));
    assert.equal(previous.rows[0].state,"ACTIVE","real process crash did not fake completion");
    await withWorkerTenant(A,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[crashId]));
    assert.equal(await processOneJob(),true);
    const actual=await req("GET","/v1/assessments/"+crashId);
    assert.equal(actual.json().status,"COMPLETED",actual.body);
    const attempts=await withTenant(A,tx=>tx.query("SELECT claim_generation,state FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[crashId]));
    assert.deepEqual(attempts.rows.map(x=>x.state),["LOST","COMPLETED"]);
   }finally{if(child.exitCode===null&&!child.killed)child.kill("SIGKILL");}
  }
 }finally{await app.close();await closeDatabase();}
});
