/** Real loopback TCP disconnect, not Fastify.inject or a simulated transport. */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {connect} from "node:net";
import {randomUUID} from "node:crypto";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,withTenant,closeDatabase} from "../packages/database/src/index.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
after(async()=>{await closeDatabase();});
test("Phase14 actual TCP disconnect mid durable admission rejects partial JSON without persisting a job",async()=>{
 await migrate();const app=await makeApp();
 const auth={authorization:"Bearer local-test-token-alpha"};
 try{
  const t=await app.inject({method:"POST",url:"/v1/targets",headers:auth,
   payload:{name:"TCP abort "+randomUUID().slice(0,8),
    baseUrl:"https://phase14-tcp-"+randomUUID()+".fixture.invalid",environment:"SYNTHETIC"}});
  assert.equal(t.statusCode,201,t.body);
  const id=t.json().id as string;
  const spec=await app.inject({method:"POST",url:"/v1/targets/"+id+"/specifications",headers:auth,
   payload:{filename:"abort.json",content:JSON.stringify({openapi:"3.1.0",info:{title:"TCP",version:"1"},
    paths:{"/health":{get:{responses:{"200":{description:"offline"}}}}}})}});
  assert.equal(spec.statusCode,201,spec.body);
  const key="aborted-"+randomUUID();
  const payload=JSON.stringify({mode:"SPEC_ONLY",specificationId:spec.json().id});
  const url=await app.listen({host:"127.0.0.1",port:0});
  const address=new URL(url),port=Number(address.port);
  const socket=connect({host:"127.0.0.1",port});
  socket.on("error",()=>{});
  await new Promise<void>((resolve,reject)=>{
   socket.once("connect",()=>resolve());socket.once("error",reject);
  });
  const header=["POST /v1/targets/"+id+"/assessments HTTP/1.1",
   "Host: 127.0.0.1:"+port,"Authorization: Bearer local-test-token-alpha",
   "Idempotency-Key: "+key,"Content-Type: application/json",
   "Content-Length: "+Buffer.byteLength(payload),"Connection: close","",""].join("\r\n");
  const closed=new Promise<void>(resolve=>socket.once("close",()=>resolve()));
  socket.write(header+payload.slice(0,Math.floor(payload.length/2)));
  socket.destroy();
  await closed;
  const found=await withTenant(A,tx=>tx.query(
   "SELECT count(*)::int AS n FROM api_assessments WHERE idempotency_key=$1",[key]));
  assert.equal(found.rows[0].n,0,"truncated accepted request must never reserve or enqueue a durable job");
  const ready=await app.inject({method:"GET",url:"/health/live"});
  assert.equal(ready.statusCode,200,"Fastify must recover after client abort");
  const wrong=await app.inject({method:"GET",url:"/v1/targets/"+id,headers:{
   authorization:"Bearer local-test-token-beta","x-tenant-id":A}});
  assert.equal(wrong.statusCode,404,"untrusted x-tenant-id must not cross tenant RLS");
  const cross=await withTenant(B,tx=>tx.query("SELECT id FROM api_targets WHERE id=$1",[id]));
  assert.equal(cross.rowCount,0);
 }finally{await app.close();}
});
