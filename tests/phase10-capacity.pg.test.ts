import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {migrate,uuid,withTenant,withWorkerTenant,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SPEC=JSON.stringify({openapi:"3.1.0",info:{title:"Worker capacity",version:"1.0.0"},
 paths:{"/alive":{get:{responses:{"200":{description:"safe"}}}}}});
test("Phase10 PG: bounded queue admission, concurrent overload, idempotency and controlled recovery",async()=>{
 await migrate();const app=await makeApp();
 const refs:string[]=[];
 const post=async(path:string,payload:object,key?:string)=>app.inject({
  method:"POST",url:path,payload,headers:{authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{})}});
 try{
  const short=randomUUID().slice(0,8);
  const t=await post("/v1/targets",{name:"Capacity "+short,
   baseUrl:"https://capacity-"+short+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(t.statusCode,201,t.body);const tid=t.json().id as string;
  const s=await post("/v1/targets/"+tid+"/specifications",
   {filename:"capacity.openapi.json",content:SPEC});
  assert.equal(s.statusCode,201,s.body);
  const sid=s.json().id as string;
  const existing=await withWorkerTenant(A,tx=>tx.query(
   "SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE tenant_id=$1",[A]));
  const slots=64-Number(existing.rows[0].n);
  assert.ok(slots>1,"queue capacity test requires fresh tenant headroom");
  await withTenant(A,async tx=>{
   for(let i=0;i<slots;i++){
    const id=uuid();refs.push(id);
    await tx.query(`INSERT INTO api_assessments
     (id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version)
      VALUES($1,$2,$3,$4,'QUEUED','SPEC_ONLY',$5,'legacy-v1')`,
     [id,A,tid,sid,"capacity-"+short+"-"+i]);
    await tx.query("SELECT public.api_enqueue_assessment($1)",[id]);
   }
  });
  const check=await withWorkerTenant(A,tx=>tx.query(
   "SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE tenant_id=$1",[A]));
  assert.equal(check.rows[0].n,64);
  const requestKey="over-cap-"+randomUUID();
  const data={specificationId:sid,mode:"SPEC_ONLY"};
  const rejected=await post("/v1/targets/"+tid+"/assessments",data,requestKey);
  assert.equal(rejected.statusCode,429,rejected.body);
  assert.equal(rejected.json().error,"QUEUE_TENANT_CAPACITY_EXCEEDED");
  const parallel=await Promise.all([post("/v1/targets/"+tid+"/assessments",data,"cap-a-"+randomUUID()),
   post("/v1/targets/"+tid+"/assessments",data,"cap-b-"+randomUUID())]);
  assert.deepEqual(parallel.map(x=>x.statusCode),[429,429]);
  const idempotent=await withTenant(A,tx=>tx.query("SELECT public.api_enqueue_assessment($1)",[refs[0]]));
  assert.equal(idempotent.rowCount,1,"idempotent accepted queue entry must not be rejected");
  // Free exactly one accepted capacity slot without refunding any fixture budget.
  const canceled=await post("/v1/assessments/"+refs[0]+"/cancel",{});
  assert.equal(canceled.statusCode,200,canceled.body);
  const admitted=await post("/v1/targets/"+tid+"/assessments",data,"admitted-"+randomUUID());
  assert.equal(admitted.statusCode,201,admitted.body);
  refs.push(admitted.json().id as string);
  const final=await withWorkerTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE tenant_id=$1",[A]));
  assert.equal(final.rows[0].n,64);
 }finally{
  if(refs.length)await withWorkerTenant(A,async tx=>{
   await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=ANY($1::uuid[])",[refs]);
   await tx.query("UPDATE api_assessments SET status='CANCELLED',completed_at=clock_timestamp() WHERE id=ANY($1::uuid[]) AND status IN('QUEUED','PROCESSING')",[refs]);
  });
  await app.close();await closeDatabase();
 }
});
