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
 closeReservation,reconcilePending,reconcileSyntheticExternalSnapshot,ingestSyntheticUsageCorrection,reserveFeatureObservation,settleFeatureObservation} from "../packages/service/src/phase13.js";
import {enqueueQaDelivery,claimQaDelivery,consumeQaSink,ackQaDelivery,failQaDelivery} from "../packages/service/src/phase13-delivery-qa.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const fixture=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
test("Phase13 PostgreSQL 18 real tenant capability and quota decisions",async t=>{
 await Promise.all([migrate(),migrate(),migrate()]);
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
  await t.test("exact 001-018 idempotent migration, FORCE RLS and no worker commercial access",async()=>{
   assert.equal((await pool.query("SELECT count(*)::int AS n FROM public.api_schema_migrations")).rows[0].n,18);
   const tabs=await pool.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname LIKE 'api_v13_%' AND relkind='r'");
   assert.equal(tabs.rowCount,11);assert(tabs.rows.every(r=>r.relrowsecurity&&r.relforcerowsecurity));
   const a=await pool.query("SELECT count(*)::int AS n FROM pg_class WHERE relname='api_pt_permits'");
   assert.equal(a.rows[0].n,1);
   const grants=await pool.query("SELECT has_table_privilege('api_family_queue','public.api_v13_usage_ledger','SELECT') AS can_read");
   assert.equal(grants.rows[0].can_read,false);
   const denied=await pool.query("SELECT has_table_privilege('api_family_queue','public.api_v13_feature_sources','SELECT') AS sources,has_table_privilege('api_family_queue','public.api_v13_qa_delivery','SELECT') AS qa");
   assert.equal(denied.rows[0].sources,false);
   assert.equal(denied.rows[0].qa,false);
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
  // A parallel race may legitimately choose either source; subsequent checks must
  // exercise the actual unconsumed source rather than assume call order.
  let unconsumedReport=r2;
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
   const chosen=(await withTenant(A,tx=>tx.query("SELECT source_report_id FROM public.api_v13_reservations WHERE id=$1",[reservation.id]))).rows[0].source_report_id as string;
   unconsumedReport=chosen===r1?r2:r1;
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
   const found=await withTenant(A,tx=>tx.query("SELECT id,delivery_state,attempt_count,last_attempt_at,delivered_at FROM api_v13_outbox"));
   assert.equal(found.rowCount,1);
   assert.equal(found.rows[0].delivery_state,"DISABLED");
   assert.equal(found.rows[0].attempt_count,0);
   assert.equal(found.rows[0].last_attempt_at,null);
   assert.equal(found.rows[0].delivered_at,null);
   await assert.rejects(()=>withTenant(A,tx=>tx.query("UPDATE api_v13_outbox SET delivery_state='PENDING' WHERE id=$1",[found.rows[0].id])));
   await assert.rejects(()=>withTenant(A,tx=>tx.query("DELETE FROM api_v13_outbox WHERE id=$1",[found.rows[0].id])));
   const noOutput=await withTenant(B,tx=>tx.query("SELECT id FROM api_v13_outbox"));
   assert.equal(noOutput.rowCount,0);
   await assert.rejects(()=>reserveObservedReport(A,randomUUID(),"phase13-no-evidence-"+randomUUID()),/IMMUTABLE_REPORT_NOT_FOUND/);
   await assert.rejects(()=>reserveObservedReport(A,unconsumedReport,"phase13-repeat-"+randomUUID()),/QUOTA_EXCEEDED/);
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
   await assert.rejects(()=>reserveObservedReport(A,unconsumedReport,"phase13-revoked-"+randomUUID()),/ENTITLEMENT_UNAVAILABLE/);
   const renewed=envelope("ISSUED",3,3);
   await ingestSyntheticEntitlement(renewed.raw,renewed.signature,key);
   const reserved=await reserveObservedReport(A,unconsumedReport,"phase13-short-"+randomUUID(),1);
   assert.equal((await projection(A)).reserved,1);
   const replay=await reserveObservedReport(A,unconsumedReport,"phase13-short-"+randomUUID(),1).then(()=>false).catch(()=>true);
   assert.equal(replay,true,"Different idempotency key for active source must not bypass reservation uniqueness");
   await new Promise(resolve=>setTimeout(resolve,1100));
   await assert.rejects(()=>settleObservedReport(A,reserved.id),/RESERVATION_EXPIRED/);
   const retry=await reserveObservedReport(A,unconsumedReport,"phase13-expiry-retry-"+randomUUID());
   assert.notEqual(retry.id,reserved.id);
   const released=await closeReservation(A,retry.id);
   assert.equal(released.state,"RELEASED");
   const retryAfterRelease=await reserveObservedReport(A,unconsumedReport,"phase13-release-retry-"+randomUUID());
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
   const third=await produceReport();
   const revocation=envelope("REVOKED",4,0);
   const conflict=await Promise.allSettled([
    reserveObservedReport(A,third,"phase13-revoke-race-"+randomUUID()),
    ingestSyntheticEntitlement(revocation.raw,revocation.signature,key)
   ]);
   assert.equal(conflict[1]?.status,"fulfilled","Revocation must commit under same tenant advisory lock");
   assert.equal((await projection(A)).quota,0,"Revocation wins all subsequent admission checks");
   if(conflict[0]?.status==="fulfilled"){
    const reservation=conflict[0].value as {id:string};
    await assert.rejects(()=>settleObservedReport(A,reservation.id),/ENTITLEMENT_UNAVAILABLE/);
   }else{
    assert.match(String((conflict[0] as PromiseRejectedResult).reason),/ENTITLEMENT_UNAVAILABLE/);
   }
   assert.equal((await projection(A)).consumed,2,"Revocation must not meter an unverified in-flight report");
  });

  await t.test("018 UTC calendar month boundary never follows the tenant or database timezone",async()=>{
   const dates=await withTenant(A,async tx=>{
    await tx.query("SET LOCAL TIME ZONE 'Pacific/Kiritimati'");
    return tx.query("SELECT date_trunc('month', $1::timestamptz AT TIME ZONE 'UTC')::date AS october, date_trunc('month',$2::timestamptz AT TIME ZONE 'UTC')::date AS november, date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')::date AS current_month",
     ["2026-10-31T23:59:59Z","2026-11-01T00:00:01Z"]);
   });
   const iso=(v:unknown)=>v instanceof Date?v.toISOString().slice(0,10):String(v).slice(0,10);
   assert.equal(iso(dates.rows[0].october),"2026-10-01");
   assert.equal(iso(dates.rows[0].november),"2026-11-01");
   assert.equal(iso((await projection(A)).monthStart),iso(dates.rows[0].current_month));
  });
  await t.test("018 genuine independent offline child observation, signed per-feature quota and replay-safe ledger",async()=>{
   const feature="OFFLINE_API_ASSESSMENT_COMPLETED",eid=randomUUID();
   const sign=(revision:number,limit:number,status:"ISSUED"|"REVOKED"="ISSUED",tenant=A)=>{
    const raw=Buffer.from(JSON.stringify({schemaVersion:V13,eventId:randomUUID(),tenantId:tenant,
     issuer:"lumicsec-ci-synthetic-v13",audience:"api-family-v13-test",
     issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+120000).toISOString(),
     entitlementId:eid,revision,feature,limit,status}));
    return {raw,sig:createHmac("sha256",key).update(raw).digest("hex")};
   };
   const grant=sign(1,1);
   assert.equal((await ingestSyntheticEntitlement(grant.raw,grant.sig,key)).replay,false);
   const reportKey=(await withTenant(A,tx=>tx.query("SELECT idempotency_key FROM public.api_v13_reservations WHERE feature='IMMUTABLE_REPORT_OBSERVED' LIMIT 1"))).rows[0].idempotency_key as string;
   await assert.rejects(()=>reserveFeatureObservation(A,r1,reportKey,feature),/IDEMPOTENCY_CONFLICT/,"cross-feature replay of a report-only key is denied");
   const race=await Promise.allSettled([
    reserveFeatureObservation(A,r1,"phase13-offline-quota-"+randomUUID(),feature),
    reserveFeatureObservation(A,r2,"phase13-offline-quota-"+randomUUID(),feature)
   ]);
   assert.equal(race.filter(x=>x.status==="fulfilled").length,1);
   assert.equal(race.filter(x=>x.status==="rejected").length,1);
   const reserved=(race.find(x=>x.status==="fulfilled") as PromiseFulfilledResult<{id:string}>).value;
   assert.equal((await settleFeatureObservation(A,reserved.id)).state,"SETTLED");
   assert.equal((await settleFeatureObservation(A,reserved.id)).replay,true);
   assert.equal((await projection(A,feature)).consumed,1);
   assert.equal((await projection(A,feature)).remaining,0);
   assert.equal((await projection(B,feature)).consumed,0);
   assert.equal((await projection(A)).consumed,2,"report-only quota remains unaffected by offline use");
   const sources=await withTenant(A,tx=>tx.query("SELECT feature,source_type,source_fingerprint,entitlement_revision FROM public.api_v13_feature_sources"));
   assert.equal(sources.rowCount,1);
   assert.equal(sources.rows[0].source_type,"PERSISTED_OFFLINE_REPORT");
   assert.match(String(sources.rows[0].source_fingerprint),/^[a-f0-9]{64}$/);
   await assert.rejects(()=>withTenant(A,tx=>tx.query("UPDATE public.api_v13_feature_sources SET entitlement_revision=3")));
   assert.equal((await withTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM public.api_v13_feature_sources"))).rows[0].n,0);
   await assert.rejects(()=>reserveFeatureObservation(A,randomUUID(),"phase13-offline-missing-"+randomUUID(),feature),/IMMUTABLE_REPORT_NOT_FOUND/);
   await assert.rejects(()=>reserveFeatureObservation(B,r1,"phase13-offline-other-"+randomUUID(),feature),/ENTITLEMENT_UNAVAILABLE/);
   const second=sign(2,2);
   await ingestSyntheticEntitlement(second.raw,second.sig,key);
   const other=race[0]?.status==="fulfilled"?r2:r1;
   const res2=await reserveFeatureObservation(A,other,"phase13-offline-second-"+randomUUID(),feature);
   await settleFeatureObservation(A,res2.id);
   assert.equal((await projection(A,feature)).consumed,2);
   assert.equal((await reconcilePending(A,feature)).state,"PENDING_EXTERNAL_AUTHORITY");
   const snapKey=randomBytes(48),now=new Date();
   const snap=Buffer.from(JSON.stringify({schemaVersion:V13,snapshotId:randomUUID(),tenantId:A,
    issuer:"lumicsec-ci-external-accounting-v13",audience:"api-family-reconcile-v13-test",
    feature,meterVersion:1,monthStart:now.toISOString().slice(0,7)+"-01",
    watermarkAt:now.toISOString(),observedUnits:2,revision:1,issuedAt:now.toISOString(),
    expiresAt:new Date(now.getTime()+100000).toISOString()}));
   assert.equal((await reconcileSyntheticExternalSnapshot(A,snap,createHmac("sha256",snapKey).update(snap).digest("hex"),snapKey)).state,"MATCHED");
   const offlineUsage=(await withTenant(A,tx=>tx.query(
    "SELECT id FROM public.api_v13_usage_ledger WHERE feature=$1 ORDER BY created_at,id LIMIT 1",[feature]))).rows[0].id as string;
   const corrKey=randomBytes(48);
   const correction=(delta:number)=>{const raw=Buffer.from(JSON.stringify({schemaVersion:V13,
    correctionId:randomUUID(),tenantId:A,issuer:"lumicsec-ci-correction-v13",
    audience:"api-family-correction-v13-test",usageId:offlineUsage,unitDelta:delta,
    reason:"MEASUREMENT_CORRECTION",issuedAt:new Date().toISOString(),
    expiresAt:new Date(Date.now()+90000).toISOString()}));
    return {raw,sig:createHmac("sha256",corrKey).update(raw).digest("hex")};};
   const less=correction(-1);
   assert.equal((await ingestSyntheticUsageCorrection(less.raw,less.sig,corrKey)).effectiveUnits,0);
   assert.equal((await projection(A,feature)).consumed,1);
   assert.equal((await projection(A)).consumed,2,"offline correction cannot alter another meter's usage");
   assert.equal((await reconcilePending(A,feature)).state,"PENDING_EXTERNAL_AUTHORITY");
   const restore=correction(1);
   assert.equal((await ingestSyntheticUsageCorrection(restore.raw,restore.sig,corrKey)).effectiveUnits,1);
   assert.equal((await projection(A,feature)).consumed,2);

  });
  await t.test("018 governed synthetic PT source requires real signed permit and successful persisted terminal",async()=>{
   const feature="GOVERNED_API_PT_COMPLETED",eid=randomUUID();
   const raw=Buffer.from(JSON.stringify({schemaVersion:V13,eventId:randomUUID(),tenantId:A,
    issuer:"lumicsec-ci-synthetic-v13",audience:"api-family-v13-test",
    issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+240000).toISOString(),
    entitlementId:eid,revision:1,feature,limit:1,status:"ISSUED"}));
   await ingestSyntheticEntitlement(raw,createHmac("sha256",key).update(raw).digest("hex"),key);
   await assert.rejects(()=>reserveFeatureObservation(A,r1,"phase13-governed-no-evidence-"+randomUUID(),feature),
    /SIGNED_GOVERNED_PT_EVIDENCE_MISSING/);
   const rawOps=await call("GET","/v2/specifications/"+specId+"/operations?limit=100");
   assert.equal(rawOps.statusCode,200,rawOps.body);
   const operations=rawOps.json() as {key:string;method:string;path:string}[];
   const operationKeys=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"].map(path=>
    operations.find(x=>x.path===path&&x.method==="GET")?.key);
   assert(operationKeys.every(Boolean));
   const scope=await ok("POST","/v6/pt/targets/"+targetId+"/scopes",{
    specificationId:specId,operationKeys,fixtureId:"pt-security-v1",exclusions:[],
    maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
   },"phase13-governed-scope-"+randomUUID());
   const scopeId=scope.id as string;
   const authorized=await call("POST","/v6/pt/scopes/"+scopeId+"/request-authorization",{});
   assert.equal(authorized.statusCode,201,authorized.body);
   const issue=await app.inject({method:"POST",url:"/v6/pt/test-authority/scopes/"+scopeId+"/issue",payload:{},
    headers:{authorization:"Bearer local-test-token-alpha","x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}});
   assert.equal(issue.statusCode,201,issue.body);
   const admitted=await ok("POST","/v11/api-vapt/assessments",{
    mode:"GOVERNED_SYNTHETIC",scopeId,policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",profile:"SECURE_BASELINE"
   },"phase13-governed-"+randomUUID());
   const governedId=admitted.id as string;
   for(let i=0;i<3;i++)assert.equal(await processOneJob(),true,"all governed parent/child workers run");
   const report=await call("GET","/v11/api-vapt/assessments/"+governedId+"/report");
   assert.equal(report.statusCode,200,report.body);
   assert.equal(report.json().status,"COMPLETED");
   const reserved=await reserveFeatureObservation(A,governedId,"phase13-governed-account-"+randomUUID(),feature);
   assert.equal((await settleFeatureObservation(A,reserved.id)).state,"SETTLED");
   assert.equal((await settleFeatureObservation(A,reserved.id)).replay,true);
   assert.equal((await projection(A,feature)).consumed,1);
   assert.equal((await projection(A,"OFFLINE_API_ASSESSMENT_COMPLETED")).consumed,2);
   const evidence=await withTenant(A,tx=>tx.query("SELECT * FROM public.api_v13_feature_sources WHERE feature=$1",[feature]));
   assert.equal(evidence.rowCount,1);
   assert.equal(evidence.rows[0].source_type,"SIGNED_GOVERNED_SYNTHETIC_PT");
   assert.match(String(evidence.rows[0].historical_permit_hash),/^[a-f0-9]{64}$/);
   const attempted=await reserveFeatureObservation(A,governedId,"phase13-governed-double-"+randomUUID(),feature).then(()=>false).catch(()=>true);
   assert.equal(attempted,true,"same committed PT terminal never counted twice");
   assert.equal((await withTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM public.api_v13_usage_ledger WHERE feature=$1",[feature]))).rows[0].n,0);
  });
  await t.test("018 synthetic QA-only retry, sink idempotency, lease fencing and dead letter; real outbox stays disabled",async()=>{
   const out=await withTenant(A,tx=>tx.query("SELECT o.id,o.delivery_state,o.attempt_count FROM public.api_v13_outbox o JOIN public.api_v13_usage_ledger l ON l.id=o.source_usage_id WHERE l.feature='OFFLINE_API_ASSESSMENT_COMPLETED' ORDER BY o.created_at,o.id"));
   assert.equal(out.rowCount,2);
   const first=await enqueueQaDelivery(A,out.rows[0].id as string);
   assert.equal((await enqueueQaDelivery(A,out.rows[0].id as string)).replay,true);
   await assert.rejects(()=>enqueueQaDelivery(B,out.rows[0].id as string),/QA_SOURCE_NOT_ELIGIBLE/);
   const lease=await claimQaDelivery(A,first.id,5);
   assert.equal(lease.state,"LEASED");
   const token=(lease as {token:string}).token;
   await assert.rejects(()=>claimQaDelivery(A,first.id),/QA_LEASE_IN_USE/);
   await assert.rejects(()=>consumeQaSink(A,first.id,randomUUID()),/QA_STALE_LEASE/);
   assert.equal((await consumeQaSink(A,first.id,token)).replay,false);
   assert.equal((await consumeQaSink(A,first.id,token)).replay,true,"synthetic delivery retry cannot duplicate receipt");
   assert.equal((await ackQaDelivery(A,first.id,token)).state,"ACKED");
   assert.equal((await ackQaDelivery(A,first.id,token)).replay,true);
   assert.equal((await claimQaDelivery(A,first.id)).state,"ACKED");
   const second=await enqueueQaDelivery(A,out.rows[1].id as string);
   const backoffs:number[]=[];
   for(let i=0;i<4;i++){
    const c=await claimQaDelivery(A,second.id,5);
    assert.equal(c.state,"LEASED");
    const result=await failQaDelivery(A,second.id,(c as {token:string}).token);
    backoffs.push(result.backoffSeconds);
    if(i<3){
     assert.equal(result.state,"RETRY");
     await assert.rejects(()=>claimQaDelivery(A,second.id),/QA_BACKOFF_ACTIVE/);
     await new Promise(resolve=>setTimeout(resolve,(result.backoffSeconds*1000)+120));
    }else assert.equal(result.state,"DEAD_LETTER");
   }
   assert.deepEqual(backoffs,[1,2,4,0]);
   assert.equal((await claimQaDelivery(A,second.id)).state,"DEAD_LETTER");
   const events=await withTenant(A,tx=>tx.query("SELECT code,attempt_count FROM public.api_v13_qa_delivery_events WHERE delivery_id=$1 ORDER BY created_at,id",[second.id]));
   assert.equal(events.rows.filter(x=>x.code==="CLAIMED").length,4);
   assert.equal(events.rows.filter(x=>x.code==="DEAD_LETTER").length,1);
   const immutable=await withTenant(A,tx=>tx.query("SELECT delivery_state,attempt_count,delivered_at,last_attempt_at FROM public.api_v13_outbox WHERE id=$1",[out.rows[0].id]));
   assert.deepEqual(immutable.rows[0],{delivery_state:"DISABLED",attempt_count:0,delivered_at:null,last_attempt_at:null});
   assert.equal((await withTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM public.api_v13_qa_delivery"))).rows[0].n,0);
   await assert.rejects(()=>withTenant(A,tx=>tx.query("DELETE FROM public.api_v13_qa_delivery WHERE id=$1",[first.id])));
  });
 }finally{await app.close();await closeDatabase();}
});
