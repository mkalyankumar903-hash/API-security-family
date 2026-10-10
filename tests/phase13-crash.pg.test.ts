/** Actual SIGKILL of isolated child processes against durable PostgreSQL16. */
import {test} from "node:test";
import assert from "node:assert/strict";
import {fork} from "node:child_process";
import {fileURLToPath} from "node:url";
import {readFileSync} from "node:fs";
import {randomBytes,randomUUID,createHmac} from "node:crypto";
import {migrate,withTenant,pool,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {reserveObservedReport,settleObservedReport,projection,ingestSyntheticEntitlement} from "../packages/service/src/phase13.js";
import {V13} from "../packages/contracts/src/commercial-v13.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const fixture=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
type ChildResult={barrier?:string;value?:Record<string,unknown>;error?:string;code:number|null;signal:string|null};
async function child(kind:string,source:string,key="",barrier=""):Promise<ChildResult>{
 const file=fileURLToPath(new URL("./helpers/phase13-crash-child.ts",import.meta.url));
 return new Promise((resolve,reject)=>{
  const proc=fork(file,[kind,A,source,key],{
   execArgv:["--import","tsx"],
   env:{...process.env,PHASE13_TEST_FAULT_STAGE:barrier},
   stdio:["ignore","pipe","pipe","ipc"]});
  let fired="",value:Record<string,unknown>|undefined,error:string|undefined,stderr="";
  const timer=setTimeout(()=>{proc.kill("SIGKILL");},25000);
  proc.stderr?.on("data",(d:Buffer)=>{stderr+=d.toString().slice(0,300);});
  proc.on("message",(m:unknown)=>{
   const msg=m as {phase13Barrier?:string;phase13Result?:Record<string,unknown>;phase13Error?:string};
   if(msg.phase13Barrier){fired=msg.phase13Barrier;proc.kill("SIGKILL");}
   if(msg.phase13Result)value=msg.phase13Result;
   if(msg.phase13Error)error=msg.phase13Error;
  });
  proc.once("error",e=>{clearTimeout(timer);reject(e);});
  proc.once("exit",(code,signal)=>{
   clearTimeout(timer);
   if(barrier){
    if(fired!==barrier||signal!=="SIGKILL")return reject(Error("EXPECTED_REAL_CHILD_TERMINATION "+JSON.stringify({kind,barrier,fired,code,signal,stderr,error})));
   }else if(code!==0||!value)return reject(Error("CHILD_RESTART_FAILED "+JSON.stringify({kind,code,signal,stderr,error})));
   resolve({barrier:fired,value,error,code,signal});
  });
 });
}
test("Phase13 018 independent PostgreSQL committed-vs-uncommitted SIGKILL recovery",async t=>{
 if(process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true")throw Error("TEST_AUTHORITY_REQUIRED");
 await migrate();await migrate();
 const versions=await pool.query("SELECT count(*)::int AS n FROM public.api_schema_migrations");
 assert.equal(versions.rows[0].n,18);
 const app=await makeApp();
 try{
  const call=async(method:"GET"|"POST",url:string,payload?:object,idem?:string)=>{
   const r=await app.inject({method,url,payload,headers:{
    authorization:"Bearer local-test-token-alpha",...(idem?{"idempotency-key":idem}:{})}});
   assert(r.statusCode===200||r.statusCode===201,r.body);
   return r.json() as {id?:string;specificationId?:string};
  };
  const target=await call("POST","/v1/targets",{
   name:"Crash-isolated",environment:"SYNTHETIC",baseUrl:"https://crash-"+randomUUID().slice(0,8)+".fixture.invalid"});
  const imported=await call("POST","/v2/targets/"+target.id+"/specifications/imports",
   {filename:"security.json",content:fixture},"phase13-crash-import-"+randomUUID());
  async function report(){
   const r=await call("POST","/v11/api-vapt/assessments",
    {mode:"OFFLINE_ONLY",targetId:target.id,specificationId:imported.specificationId},"phase13-crash-"+randomUUID());
   assert.equal(await processOneJob(),true);
   assert.equal(await processOneJob(),true);
   await call("GET","/v11/api-vapt/assessments/"+r.id+"/report");
   return r.id!;
  }
  const [r1,r2,r3,r4]=[await report(),await report(),await report(),await report()];
  const key=randomBytes(48),eid=randomUUID();
  const raw=Buffer.from(JSON.stringify({schemaVersion:V13,eventId:randomUUID(),tenantId:A,
   issuer:"lumicsec-ci-synthetic-v13",audience:"api-family-v13-test",
   issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+240000).toISOString(),
   entitlementId:eid,revision:1,feature:"IMMUTABLE_REPORT_OBSERVED",limit:4,status:"ISSUED"}));
  await ingestSyntheticEntitlement(raw,createHmac("sha256",key).update(raw).digest("hex"),key);
  const idem1="phase13-crash-reserve-"+randomUUID();
  await t.test("kill BEFORE reservation commit rolls back reservation, retry reserves exactly one",async()=>{
   await child("reserve",r1,idem1,"phase13-reserve:before-commit");
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_v13_reservations"))).rows[0].n,0);
  });
  const one=await reserveObservedReport(A,r1,idem1);
  const idem2="phase13-crash-lost-ack-"+randomUUID();
  await t.test("kill AFTER reservation COMMIT before response: identical idempotency returns committed row",async()=>{
   await child("reserve",r2,idem2,"phase13-reserve:after-commit");
   const replay=await child("reserve",r2,idem2);
   assert.equal(replay.value?.replay,true);
   assert.equal((await projection(A)).reserved,2);
  });
  const two=await reserveObservedReport(A,r2,idem2);
  await t.test("kill AFTER ledger write BEFORE outbox insert atomically rolls back all settlement",async()=>{
   await child("settle",one.id,"","phase13-settle:between-ledger-outbox");
   const after=await withTenant(A,tx=>tx.query("SELECT (SELECT count(*) FROM public.api_v13_usage_ledger)::int AS ledger,(SELECT count(*) FROM public.api_v13_outbox)::int AS outbox,(SELECT state FROM public.api_v13_reservations WHERE id=$1) AS state",[one.id]));
   assert.deepEqual(after.rows[0],{ledger:0,outbox:0,state:"RESERVED"});
   assert.equal((await settleObservedReport(A,one.id)).replay,false);
  });
  await t.test("kill AFTER ledger + outbox COMMIT but before ACK: restart observes exactly-once",async()=>{
   await child("settle",two.id,"","phase13-settle:after-commit");
   const replay=await child("settle",two.id);
   assert.equal(replay.value?.replay,true);
   const totals=await withTenant(A,tx=>tx.query("SELECT (SELECT count(*) FROM public.api_v13_usage_ledger)::int AS ledger,(SELECT count(*) FROM public.api_v13_outbox)::int AS outbox"));
   assert.deepEqual(totals.rows[0],{ledger:2,outbox:2});
  });
  await t.test("kill during persisted expiry recovery: rollback then fresh child recovers",async()=>{
   const exp=await reserveObservedReport(A,r3,"phase13-crash-exp-"+randomUUID(),1);
   await new Promise(resolve=>setTimeout(resolve,1250));
   const idem="phase13-crash-recover-"+randomUUID();
   await child("reserve",r4,idem,"phase13-reserve:before-commit");
   const before=await withTenant(A,tx=>tx.query("SELECT state FROM public.api_v13_reservations WHERE id=$1",[exp.id]));
   assert.equal(before.rows[0].state,"RESERVED");
   const recovered=await child("reserve",r4,idem);
   assert.equal(recovered.value?.replay,false);
   const after=await withTenant(A,tx=>tx.query("SELECT state FROM public.api_v13_reservations WHERE id=$1",[exp.id]));
   assert.equal(after.rows[0].state,"EXPIRED");
   assert.equal((await projection(A)).reserved,1);
  });
  await t.test("test-only synthetic sink crash after durable receipt before ACK recovers with one receipt",async()=>{
   const out=await withTenant(A,tx=>tx.query("SELECT id,delivery_state FROM public.api_v13_outbox ORDER BY created_at,id LIMIT 1"));
   assert.equal(out.rows[0].delivery_state,"DISABLED");
   await child("qa-after-sink",out.rows[0].id as string,"","phase13-qa:after-sink-before-ack");
   await new Promise(resolve=>setTimeout(resolve,1250));
   const retried=await child("qa-after-sink",out.rows[0].id as string,"");
   const result=retried.value as {sent:{replay:boolean};ack:{state:string}};
   assert.equal(result.sent.replay,true);
   assert.equal(result.ack.state,"ACKED");
   const receipt=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM public.api_v13_qa_sink_receipts"));
   assert.equal(receipt.rows[0].n,1);
   assert.equal((await withTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM public.api_v13_qa_sink_receipts"))).rows[0].n,0);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM public.api_v13_outbox WHERE delivery_state='DISABLED' AND attempt_count=0"))).rows[0].n,2);
  });
 }finally{await app.close();await closeDatabase();}
});
