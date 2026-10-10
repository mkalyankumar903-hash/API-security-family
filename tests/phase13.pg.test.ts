/** Real PostgreSQL16 tenant isolation, signed event replay, concurrent quota and source ledger. */
import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID,randomBytes,createHmac} from "node:crypto";
import {migrate,withTenant,pool,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {V13} from "../packages/contracts/src/commercial-v13.js";
import {ingestSyntheticEntitlement,projection,reserveObservedReport,settleObservedReport,
 closeReservation,reconcilePending,reconcileSyntheticExternalSnapshot,ingestSyntheticUsageCorrection} from "../packages/service/src/phase13.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const fixture=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
test("Phase13 PostgreSQL 17 real tenant capability and quota decisions",async t=>{
 await migrate();await migrate();
 const app=await makeApp(),key=randomBytes(48),entitlementId=randomUUID();
 const call=(method:"GET"|"POST",url:string,payload?:unknown,beta=false,idem?:string)=>
  app.inject({method,url,payload:payload as object|undefined,headers:{
   authorization:"Bearer "+(beta?"local-test-token-beta":"local-test-token-alpha"),
   ...(idem?{"idempotency-key":idem}:{})}});
 const ok=async(method:"GET"|"POST",url:string,payload?:unknown,idem?:string)=>{
  const r=await call(method,url,payload,false,idem);assert(r.statusCode===200||r.statusCode===201,r.body);
  return r.json() as Record<string,unknown>;
 };
 const envelope=(status:"ISSUED"|"REVOKED",rev:number,limit:number)=>{
  const raw=Buffer.from(JSON.stringify({schemaVersion:V13,eventId:randomUUID(),tenantId:A,
   issuer:"lumicsec-ci-synthetic-v13",audience:"api-family-v13-test",
   issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+180000).toISOString(),
   entitlementId,revision:rev,feature:"IMMUTABLE_REPORT_OBSERVED",limit,status}));
  return {raw,signature:createHmac("sha256",key).update(raw).digest("hex")};
 };
 try{
  await t.test("exact 001-017 idempotent migration, FORCE RLS and no worker commercial access",async()=>{
   assert.equal((await pool.query("SELECT count(*)::int AS n FROM public.api_schema_migrations")).rows[0].n,17);
   const tabs=await pool.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname LIKE 'api_v13_%' AND relkind='r'");
   assert.equal(tabs.rowCount,7);assert(tabs.rows.every(r=>r.relrowsecurity&&r.relforcerowsecurity));
   const a=await pool.query("SELECT count(*)::int AS n FROM pg_class WHERE relname='api_pt_permits'");
   assert.equal(a.rows[0].n,1);
   const grants=await pool.query("SELECT has_table_privilege('api_family_queue','public.api_v13_usage_ledger','SELECT') AS can_read");
   assert.equal(grants.rows[0].can_read,false);
  });
  assert.equal((await call("GET","/v13/decisions")).json().allowed,false);
  assert.equal((await call("GET","/v13/decisions")).json().code,"HOST_AUTHORITY_NOT_CONFIGURED");
  assert.equal((await call("GET","/v13/usage/events?limit=101")).statusCode,400);
  assert.equal((await call("GET","/v13/capabilities",undefined,true)).statusCode,200);
  assert.equal((await call("GET","/v13/usage/summary")).headers["cache-control"],"no-store");
  const target=await ok("POST","/v1/targets",{name:"Phase13 synthetic real PG",environment:"SYNTHETIC",
   baseUrl:"https://phase13-"+randomUUID().slice(0,8)+".fixture.invalid"});
  const targetId=target.id as string;
  const importResult=await ok("POST","/v2/targets/"+targetId+"/specifications/imports",
   {filename:"security.json",content:fixture},"phase13-import-"+randomUUID());
  const specId=importResult.specificationId as string;
  async function produceReport(){
   const run=await ok("POST","/v11/api-vapt/assessments",
    {mode:"OFFLINE_ONLY",targetId,specificationId:specId},"phase13-offline-"+randomUUID());
   const reportId=run.id as string;
   assert.equal(await processOneJob(),true);
   assert.equal(await processOneJob(),true);
   const response=await call("GET","/v11/api-vapt/assessments/"+reportId+"/report");
   assert.equal(response.statusCode,200,response.body);
   return reportId;
  }
  const r1=await produceReport(),r2=await produceReport();
  const initial=await call("GET","/v13/usage/summary");
  assert.equal(initial.json().quota,0);
  const first=envelope("ISSUED",1,1);
  await t.test("exact-byte event signature, idempotency, tamper, revision order, fail-closed",async()=>{
   assert.deepEqual(await ingestSyntheticEntitlement(first.raw,first.signature,key),{eventId:JSON.parse(first.raw.toString()).eventId,replay:false});
   assert.equal((await ingestSyntheticEntitlement(first.raw,first.signature,key)).replay,true);
   const changed=Buffer.from(first.raw.toString().replace('"limit":1','"limit":2'));
   await assert.rejects(()=>ingestSyntheticEntitlement(changed,first.signature,key),/INVALID_EVENT_SIGNATURE/);
   await assert.rejects(()=>ingestSyntheticEntitlement(first.raw,"0".repeat(64),key),/INVALID_EVENT_SIGNATURE/);
   const future=envelope("ISSUED",4,1);
   await assert.rejects(()=>ingestSyntheticEntitlement(future.raw,future.signature,key),/ENTITLEMENT_REVISION_CONFLICT/);
   assert.equal((await call("GET","/v13/decisions")).json().allowed,false);
   assert.equal((await projection(B)).entitlement,null);
  });
  await t.test("true PostgreSQL parallel contention, exactly one reservation, source dedupe and settlement",async()=>{
   const racers=await Promise.allSettled([
    reserveObservedReport(A,r1,"phase13-reserve-"+randomUUID()),
    reserveObservedReport(A,r2,"phase13-reserve-"+randomUUID())]);
   const wins=racers.filter(x=>x.status==="fulfilled");
   const losses=racers.filter(x=>x.status==="rejected");
   assert.equal(wins.length,1,JSON.stringify(racers));assert.equal(losses.length,1);
   assert.match(String((losses[0] as PromiseRejectedResult).reason),/QUOTA_EXCEEDED/);
   const reservation=(wins[0] as PromiseFulfilledResult<{id:string;state:string}>).value;
   assert.equal((await projection(A)).reserved,1);
   const a=await settleObservedReport(A,reservation.id);
   assert.equal(a.state,"SETTLED");
   assert.equal((await settleObservedReport(A,reservation.id)).replay,true);
   const usage=await call("GET","/v13/usage/events?limit=10");
   assert.equal(usage.statusCode,200,usage.body);
   assert.equal((usage.json() as unknown as unknown[]).length,1);
   assert.equal((await projection(A)).consumed,1);
   assert.equal((await projection(A)).remaining,0);
   const other=await call("GET","/v13/usage/events",undefined,true);
   assert.deepEqual(other.json(),[]);
   const found=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_v13_outbox"));
   assert.equal(found.rows[0].n,1);
   await assert.rejects(()=>reserveObservedReport(A,r2,"phase13-repeat-"+randomUUID()),/QUOTA_EXCEEDED/);
   assert.equal((await call("GET","/v13/reservations",undefined,true)).body,"[]");
  });
  await t.test("independent signed accounting snapshot mismatch, replay and stale revision",async()=>{
   const accountKey=randomBytes(48);
   const makeSnapshot=(revision:number,units:number,tenant=A)=>{
    const raw=Buffer.from(JSON.stringify({schemaVersion:V13,snapshotId:randomUUID(),tenantId:tenant,
     issuer:"lumicsec-ci-external-accounting-v13",audience:"api-family-reconcile-v13-test",
     feature:"IMMUTABLE_REPORT_OBSERVED",meterVersion:1,
     monthStart:new Date().toISOString().slice(0,7)+"-01",
     watermarkAt:new Date().toISOString(),observedUnits:units,revision,
     issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+120000).toISOString()}));
    return {raw,signature:createHmac("sha256",accountKey).update(raw).digest("hex")};
   };
   const external=makeSnapshot(1,0);
   const mismatch=await reconcileSyntheticExternalSnapshot(A,external.raw,external.signature,accountKey);
   assert.equal(mismatch.state,"MISMATCH");
   assert.equal((await reconcileSyntheticExternalSnapshot(A,external.raw,external.signature,accountKey)).replay,true);
   const stale=makeSnapshot(1,1);
   await assert.rejects(()=>reconcileSyntheticExternalSnapshot(A,stale.raw,stale.signature,accountKey),/SNAPSHOT_REVISION_CONFLICT/);
   const cross=makeSnapshot(2,1,B);
   await assert.rejects(()=>reconcileSyntheticExternalSnapshot(A,cross.raw,cross.signature,accountKey),/SNAPSHOT_TENANT_MISMATCH/);
   const good=makeSnapshot(2,1);
   const compared=await reconcileSyntheticExternalSnapshot(A,good.raw,good.signature,accountKey);
   assert.equal(compared.state,"MATCHED");assert.equal(compared.syntheticExternalOnly,true);
   const outdated=makeSnapshot(1,1);
   await assert.rejects(()=>reconcileSyntheticExternalSnapshot(A,outdated.raw,outdated.signature,accountKey),/SNAPSHOT_STALE_REVISION/);
   assert.equal((await call("GET","/v13/reconciliations",undefined,true)).body,"[]");
  });
  await t.test("immutable usage, tenant RLS, pending not self-matched and revoked state",async()=>{
   const firstPending=await reconcilePending(A),again=await reconcilePending(A);
   assert.equal(firstPending.state,"PENDING_EXTERNAL_AUTHORITY");
   assert.equal(again.id,firstPending.id);
   assert.equal((await call("GET","/v13/reconciliations",undefined,true)).body,"[]");
   const ledger=await withTenant(A,tx=>tx.query("SELECT id,source_fingerprint FROM api_v13_usage_ledger"));
   assert.equal(ledger.rowCount,1);
   assert.match(ledger.rows[0].source_fingerprint,/^[a-f0-9]{64}$/);
   await assert.rejects(()=>withTenant(A,tx=>tx.query("DELETE FROM api_v13_usage_ledger WHERE id=$1",[ledger.rows[0].id])));
   const cross=await withTenant(B,tx=>tx.query("SELECT id FROM api_v13_usage_ledger"));
   assert.equal(cross.rowCount,0);
   const revoked=envelope("REVOKED",2,0);
   await ingestSyntheticEntitlement(revoked.raw,revoked.signature,key);
   assert.equal((await projection(A)).quota,0);
   await assert.rejects(()=>reserveObservedReport(A,r2,"phase13-revoked-"+randomUUID()),/ENTITLEMENT_UNAVAILABLE/);
   const renewed=envelope("ISSUED",3,3);
   await ingestSyntheticEntitlement(renewed.raw,renewed.signature,key);
   const reserved=await reserveObservedReport(A,r2,"phase13-short-"+randomUUID(),1);
   assert.equal((await projection(A)).reserved,1);
   const replay=await reserveObservedReport(A,r2,"phase13-short-"+randomUUID(),1).then(()=>false).catch(()=>true);
   assert.equal(replay,true,"Different idempotency key for active source must not bypass reservation uniqueness");
   await new Promise(resolve=>setTimeout(resolve,1100));
   await assert.rejects(()=>settleObservedReport(A,reserved.id),/RESERVATION_EXPIRED/);
   const retry=await reserveObservedReport(A,r2,"phase13-expiry-retry-"+randomUUID());
   assert.notEqual(retry.id,reserved.id);
   const released=await closeReservation(A,retry.id);
   assert.equal(released.state,"RELEASED");
   const retryAfterRelease=await reserveObservedReport(A,r2,"phase13-release-retry-"+randomUUID());
   assert.equal((await settleObservedReport(A,retryAfterRelease.id)).state,"SETTLED");
   assert.equal((await projection(A)).consumed,2);
   const late=await reconcilePending(A);
   assert.notEqual(late.id,firstPending.id,"Late-arriving usage must generate new immutable pending evidence");
   const original=await withTenant(A,tx=>tx.query("SELECT id,units FROM public.api_v13_usage_ledger ORDER BY created_at DESC LIMIT 1"));
   assert.equal(original.rowCount,1);
   const usageId=original.rows[0].id as string,correctionKey=randomBytes(48);
   const signCorrection=(delta:number,tenant=A,correctionId:string=randomUUID())=>{
    const raw=Buffer.from(JSON.stringify({schemaVersion:V13,correctionId,tenantId:tenant,
     issuer:"lumicsec-ci-correction-v13",audience:"api-family-correction-v13-test",
     usageId,unitDelta:delta,reason:"MEASUREMENT_CORRECTION",
     issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+120000).toISOString()}));
    return {raw,signature:createHmac("sha256",correctionKey).update(raw).digest("hex")};
   };
   const correction=signCorrection(-1);
   assert.equal((await ingestSyntheticUsageCorrection(correction.raw,correction.signature,correctionKey)).effectiveUnits,0);
   assert.equal((await ingestSyntheticUsageCorrection(correction.raw,correction.signature,correctionKey)).replay,true);
   assert.equal((await projection(A)).consumed,1,"Append-only correction must adjust local usage without deleting history");
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM public.api_v13_usage_ledger"))).rows[0].n,2);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM public.api_v13_usage_corrections"))).rows[0].n,1);
   assert.equal((await call("GET","/v13/usage/corrections",undefined,true)).body,"[]");
   assert.equal((await call("GET","/v13/usage/corrections")).statusCode,200);
   await assert.rejects(()=>ingestSyntheticUsageCorrection(correction.raw,"f".repeat(64),correctionKey),/INVALID_CORRECTION_SIGNATURE/);
   const collision=signCorrection(1,A,JSON.parse(correction.raw.toString()).correctionId as string);
   await assert.rejects(()=>ingestSyntheticUsageCorrection(collision.raw,collision.signature,correctionKey),/CORRECTION_ID_REUSE_CONFLICT/);
   const crossCorrection=signCorrection(-1,B);
   await assert.rejects(()=>ingestSyntheticUsageCorrection(crossCorrection.raw,crossCorrection.signature,correctionKey),/USAGE_SOURCE_NOT_FOUND/);
   const overdrawn=signCorrection(-1);
   await assert.rejects(()=>ingestSyntheticUsageCorrection(overdrawn.raw,overdrawn.signature,correctionKey),/INVALID_USAGE_CORRECTION/);
   await assert.rejects(()=>withTenant(A,tx=>tx.query("DELETE FROM public.api_v13_usage_corrections")));
   const pendingCorrection=await reconcilePending(A);
   assert.notEqual(pendingCorrection.id,late.id,"Correction is distinct immutable pending reconciliation evidence");
   const restore=signCorrection(1);
   assert.equal((await ingestSyntheticUsageCorrection(restore.raw,restore.signature,correctionKey)).effectiveUnits,1);
   assert.equal((await projection(A)).consumed,2);
   const excessive=signCorrection(1);
   await assert.rejects(()=>ingestSyntheticUsageCorrection(excessive.raw,excessive.signature,correctionKey),/INVALID_USAGE_CORRECTION/);
   assert.equal((await call("GET","/v13/decisions")).json().allowed,false);
  });
 }finally{await app.close();await closeDatabase();}
});
