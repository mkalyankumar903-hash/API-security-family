import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {Pool} from "pg";
import {issueTestPermit,verifyTestPermit,verifyStoredTestPermit,digest} from "../packages/pt/src/permit.js";

test("Phase08 populated Phase07 011 -> 012 upgrade preserves historic signed permits, assessment reports and synthetic detection plans",async()=>{
 const root=process.env.MIGRATION_DATABASE_URL;
 if(!root)throw new Error("MIGRATION_DATABASE_URL_REQUIRED");
 const admin=new Pool({connectionString:root,max:1});
 const name="phase08_upgrade_"+randomUUID().replaceAll("-","").slice(0,18);
 const url=new URL(root);url.pathname="/"+name;
 const clone=new Pool({connectionString:url.toString(),max:1});
 let created=false;
 try{
  await admin.query("CREATE DATABASE "+name);
  created=true;
  await clone.query("CREATE TABLE api_schema_migrations(version text PRIMARY KEY)");
  for(let i=0;i<8;i++){
   const files=[
    "001_phase0.sql","002_queue_isolation.sql","003_phase1_target_onboarding.sql",
    "004_phase2_offline_discovery.sql","005_phase3_deterministic_detection.sql",
    "006_phase4_authenticated_fixture.sql","007_phase5_unified_assessment.sql",
    "008_phase5_rich_offline.sql"
   ];
   const sql=readFileSync(new URL("../packages/database/migrations/"+files[i],import.meta.url),"utf8");
   await clone.query(sql);
   await clone.query("INSERT INTO api_schema_migrations(version) VALUES($1)",[String(i+1).padStart(3,"0")]);
  }
  const tenant="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const target=randomUUID(),spec=randomUUID(),assessment=randomUUID(),evidence=randomUUID(),finding=randomUUID(),report=randomUUID();
  await clone.query("INSERT INTO api_targets(id,tenant_id,name,base_url,environment) VALUES($1,$2,'Preserved Phase05','https://upgrade.fixture.invalid','SYNTHETIC')",
   [target,tenant]);
  await clone.query("INSERT INTO api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,'old.json','OPENAPI_3_0',$4,'{}')",
   [spec,tenant,target,"a".repeat(64)]);
  await clone.query("INSERT INTO api_spec_inventories(specification_id,tenant_id,target_id,version_number,original_format,raw_fingerprint,normalized_fingerprint,normalization_version,snapshot,assessment_source,coverage,selected) VALUES($1,$2,$3,1,'OPENAPI_3_0',$4,$5,'phase02-v1','{}'::jsonb,'OpenAPI','SUPPORTED_PROFILE',true)",
   [spec,tenant,target,"a".repeat(64),"b".repeat(64)]);
  await clone.query("INSERT INTO api_rich_inventories(specification_id,tenant_id,target_id,raw_fingerprint,phase02_fingerprint,rich_fingerprint,snapshot) VALUES($1,$2,$3,$4,$5,$6,'{}'::jsonb)",
   [spec,tenant,target,"a".repeat(64),"b".repeat(64),"c".repeat(64)]);
  await clone.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version) VALUES($1,$2,$3,$4,'COMPLETED','SPEC_ONLY','pre-phase6-immutable-report','legacy-v1')",
   [assessment,tenant,target,spec]);
  await clone.query("INSERT INTO api_evidence(id,tenant_id,assessment_id,fingerprint,pointer,content_json) VALUES($1,$2,$3,$4,'/paths','{}'::jsonb)",
   [evidence,tenant,assessment,"d".repeat(64)]);
  await clone.query("INSERT INTO api_findings(id,tenant_id,assessment_id,evidence_id,rule_id,category,explanation,remediation,confidence,validation_level,review_required) VALUES($1,$2,$3,$4,'BASELINE','SPEC','Old observation','Review','SPEC_OBSERVATION','SPEC_ONLY',true)",
   [finding,tenant,assessment,evidence]);
  await clone.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",
   [report,tenant,assessment,JSON.stringify({phase:5,history:"preserved"})]);
  const migrate9=readFileSync(new URL("../packages/database/migrations/009_phase6_pt_safe_execution.sql",import.meta.url),"utf8");
  await clone.query("BEGIN");
  try{
   await clone.query(migrate9);
   await clone.query("INSERT INTO api_schema_migrations(version) VALUES('009')");
   // Qualified populated 009->010 transition: an existing genuine MAC-bound
   // synthetic permit survives without keeping its bearer or signature.
   const oldScope=randomUUID(),oldPermit=randomUUID(),issuedAt=Date.now();
   const current=await clone.query("SELECT verification_version,scope_revision FROM api_targets WHERE id=$1",[target]);
   const claimsInput={
    permitId:oldPermit,tenantId:tenant,targetId:target,environment:"SYNTHETIC" as const,
    fixtureId:"billing-safe-v1" as const,specificationId:spec,specificationVersion:1,
    specFingerprint:"a".repeat(64),targetVerificationVersion:current.rows[0].verification_version,
    targetScopeRevision:current.rows[0].scope_revision,scopeId:oldScope,
    operationKeys:["GET /status"],methods:["GET","HEAD"] as ("GET"|"HEAD")[],
    exclusions:[],maxEvaluations:1,maxConcurrency:1,ratePerMinute:1,
    deadlineMs:10000,notBefore:issuedAt-1000,expiresAt:issuedAt+300000
   };
   const originalBearer=issueTestPermit(claimsInput);
   const originalClaims=verifyTestPermit(originalBearer);
   await clone.query(
    "INSERT INTO api_pt_scopes(id,tenant_id,target_id,specification_id,specification_version,spec_fingerprint,target_verification_version,target_scope_revision,environment,fixture_id,profile,operation_keys,exclusions,max_evaluations,max_concurrency,rate_per_minute,deadline_ms,validity_minutes,idempotency_key) VALUES($1,$2,$3,$4,1,$5,$6,$7,'SYNTHETIC','billing-safe-v1','SYNTHETIC_PT_READ_ONLY',$8::jsonb,'[]'::jsonb,1,1,1,10000,5,$9)",
    [oldScope,tenant,target,spec,"a".repeat(64),claimsInput.targetVerificationVersion,
     claimsInput.targetScopeRevision,JSON.stringify(claimsInput.operationKeys),"old-permit-"+randomUUID()]);
   await clone.query(
    "INSERT INTO api_pt_permits(id,tenant_id,scope_id,signed_token,token_hash,claims,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,to_timestamp($7::double precision/1000),to_timestamp($8::double precision/1000))",
    [oldPermit,tenant,oldScope,originalBearer,digest(originalBearer),JSON.stringify(originalClaims),issuedAt,claimsInput.expiresAt]);
   await clone.query(readFileSync(new URL("../packages/database/migrations/010_phase6_permit_storage_hardening.sql",import.meta.url),"utf8"));
   const upgraded=await clone.query("SELECT claims,token_hash,signed_body FROM api_pt_permits WHERE id=$1",[oldPermit]);
   assert.equal(upgraded.rowCount,1);
   assert.equal(upgraded.rows[0].signed_body,originalBearer.split(".")[1]);
   assert.deepEqual(verifyStoredTestPermit(upgraded.rows[0].claims,upgraded.rows[0].token_hash,upgraded.rows[0].signed_body),originalClaims);
   assert.equal((await clone.query("SELECT count(*)::int AS n FROM information_schema.columns WHERE table_name='api_pt_permits' AND column_name='signed_token'")).rows[0].n,0);
   await clone.query("INSERT INTO api_schema_migrations(version) VALUES('010')");
   await clone.query("COMMIT");
  }catch(e){await clone.query("ROLLBACK");throw e;}
  // The Phase06 database is now POPULATED at exactly schema version 010.
  // Apply the unchanged Phase07 migration on the populated clone, not a fresh schema.
  assert.equal((await clone.query("SELECT count(*)::int AS n FROM api_schema_migrations")).rows[0].n,10);
  await clone.query("BEGIN");
  try{
   await clone.query(readFileSync(new URL("../packages/database/migrations/011_phase7_pt_detection.sql",import.meta.url),"utf8"));
   await clone.query("INSERT INTO api_schema_migrations(version) VALUES('011')");
   await clone.query("COMMIT");
  }catch(error){await clone.query("ROLLBACK");throw error;}
  // Populate a historical Phase07 synthetic detection plan and immutable report as a migration fixture.
  // This deliberately does not issue Host permits or access customer endpoints.
  const historicalScope=randomUUID(),historicalPermit=randomUUID(),historicalJob=randomUUID(),historicalReport=randomUUID();
  const historicTarget=await clone.query("SELECT verification_version,scope_revision FROM api_targets WHERE id=$1",[target]);
  const historicTime=Date.now();
  const historicalPolicy={permitId:historicalPermit,tenantId:tenant,targetId:target,
   environment:"SYNTHETIC" as const,fixtureId:"pt-security-v1" as const,
   specificationId:spec,specificationVersion:1,specFingerprint:"a".repeat(64),
   targetVerificationVersion:historicTarget.rows[0].verification_version,
   targetScopeRevision:historicTarget.rows[0].scope_revision,scopeId:historicalScope,
   operationKeys:["GET /pt/account"],methods:["GET","HEAD"] as ("GET"|"HEAD")[],
   exclusions:[],maxEvaluations:2,maxConcurrency:1,ratePerMinute:2,deadlineMs:10000,
   notBefore:historicTime-1000,expiresAt:historicTime+300000};
  const syntheticBearer=issueTestPermit(historicalPolicy),syntheticClaims=verifyTestPermit(syntheticBearer);
  await clone.query(
   "INSERT INTO api_pt_scopes(id,tenant_id,target_id,specification_id,specification_version,spec_fingerprint,target_verification_version,target_scope_revision,environment,fixture_id,profile,operation_keys,exclusions,max_evaluations,max_concurrency,rate_per_minute,deadline_ms,validity_minutes,idempotency_key) VALUES($1,$2,$3,$4,1,$5,$6,$7,'SYNTHETIC','pt-security-v1','SYNTHETIC_PT_READ_ONLY',$8::jsonb,'[]'::jsonb,2,1,2,10000,5,$9)",
   [historicalScope,tenant,target,spec,"a".repeat(64),historicalPolicy.targetVerificationVersion,historicalPolicy.targetScopeRevision,
    JSON.stringify(["GET /pt/account"]),"pt8-upgrade-"+randomUUID()]);
  await clone.query(
   "INSERT INTO api_pt_permits(id,tenant_id,scope_id,token_hash,claims,signed_body,issued_at,expires_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,to_timestamp($7::double precision/1000),to_timestamp($8::double precision/1000))",
   [historicalPermit,tenant,historicalScope,digest(syntheticBearer),JSON.stringify(syntheticClaims),
    syntheticBearer.split(".")[1],historicTime,historicalPolicy.expiresAt]);
  await clone.query(
   "INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version) VALUES($1,$2,$3,$4,'COMPLETED','SYNTHETIC_PT_FIXTURE',$5,'pt-detection-v1')",
   [historicalJob,tenant,target,spec,"pt8-detection-"+randomUUID()]);
  await clone.query(
   "INSERT INTO api_pt_jobs(assessment_id,tenant_id,target_id,scope_id,permit_id,operation_keys,job_deadline) VALUES($1,$2,$3,$4,$5,$6::jsonb,now()+interval '2 minutes')",
   [historicalJob,tenant,target,historicalScope,historicalPermit,JSON.stringify(["GET /pt/account"])]);
  await clone.query(
   "INSERT INTO api_pt_detection_plans(assessment_id,tenant_id,fixture_version,fixture_profile,engine_version,rules,evaluations,plan_fingerprint) VALUES($1,$2,1,'SECURE_BASELINE','pt-detection-v1',$3::jsonb,$4::jsonb,$5)",
   [historicalJob,tenant,JSON.stringify([{id:"PT-AUTH-ANONYMOUS",revision:"1.0.0"}]),
    JSON.stringify([{evaluationKey:"PT-AUTH-ANONYMOUS:valid",ruleId:"PT-AUTH-ANONYMOUS",caseId:"valid",operationKey:"GET /pt/account",method:"GET",path:"/pt/account",actor:"alice"}]),"e".repeat(64)]);
  const historicalProjection={schemaVersion:"pt-detection-report-v1",status:"COMPLETED",
   assessmentId:historicalJob,validationLevel:"SYNTHETIC_PT_OBSERVATION",
   syntheticOnly:true,verifiedFixed:false,customerNetworkRequests:0,
   observations:[],migrationFixture:"HISTORICAL_IMMUTABILITY_ONLY"};
  await clone.query(
   "INSERT INTO api_pt_detection_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",
   [historicalReport,tenant,historicalJob,JSON.stringify(historicalProjection)]);
  // Real forward-only 011 -> 012 transition on a populated Phase07 database.
  assert.equal((await clone.query("SELECT count(*)::int AS n FROM api_schema_migrations")).rows[0].n,11);
  await clone.query("BEGIN");
  try{
   await clone.query(readFileSync(new URL("../packages/database/migrations/012_phase8_complete_pt_product.sql",import.meta.url),"utf8"));
   await clone.query("INSERT INTO api_schema_migrations(version) VALUES('012')");
   await clone.query("COMMIT");
  }catch(error){await clone.query("ROLLBACK");throw error;}
  const unchanged=await clone.query("SELECT projection FROM api_pt_detection_reports WHERE id=$1",[historicalReport]);
  assert.deepEqual(unchanged.rows[0].projection,historicalProjection);
  assert.equal((await clone.query("SELECT count(*)::int AS n FROM api_pt_detection_plans WHERE assessment_id=$1",[historicalJob])).rows[0].n,1);
  assert.equal((await clone.query("SELECT count(*)::int AS n FROM api_pt8_terminal_coverage")).rows[0].n,0);
  const terminalSecurity=await clone.query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='public.api_pt8_terminal_coverage'::regclass");
  assert.equal(terminalSecurity.rows[0].relrowsecurity,true);
  assert.equal(terminalSecurity.rows[0].relforcerowsecurity,true);
  assert.equal((await clone.query("SELECT has_table_privilege('api_family','public.api_pt8_terminal_coverage','UPDATE') AS allowed")).rows[0].allowed,false);
  await assert.rejects(()=>clone.query("UPDATE api_pt_detection_reports SET projection='{}'::jsonb WHERE id=$1",[historicalReport]),/PHASE1_IMMUTABLE/);
  const pt7=await clone.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relkind='r' AND relname LIKE 'api_pt_detection_%' ORDER BY relname");
  assert.equal(pt7.rowCount,4);
  assert.ok(pt7.rows.every(x=>x.relrowsecurity===true&&x.relforcerowsecurity===true));
  for(const table of ["api_pt_detection_plans","api_pt_detection_evaluations","api_pt_detection_results","api_pt_detection_reports"]){
   assert.equal((await clone.query("SELECT count(*)::int AS n FROM public."+table)).rows[0].n,0,
    table+" must not fabricate new historical findings");
  }
  assert.equal((await clone.query("SELECT has_table_privilege('api_family','public.api_pt_detection_reports','INSERT') AS allowed")).rows[0].allowed,false);
  assert.equal((await clone.query("SELECT has_table_privilege('api_family_queue','public.api_pt_detection_reports','INSERT') AS allowed")).rows[0].allowed,true);
  const oldPermitPersisted=await clone.query("SELECT claims,token_hash,signed_body FROM api_pt_permits");
  assert.equal(oldPermitPersisted.rowCount,1);
  const preserved=oldPermitPersisted.rows[0];
  assert.ok(verifyStoredTestPermit(preserved.claims,preserved.token_hash,preserved.signed_body));
  const assessmentEngine=await clone.query("SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conname='api_assessments_engine_version_check'");
  assert.match(assessmentEngine.rows[0].definition,/pt-detection-v1/);
  for(const [table,where,id] of [
   ["api_targets","id",target],["api_specifications","id",spec],
   ["api_spec_inventories","specification_id",spec],["api_rich_inventories","specification_id",spec],
   ["api_assessments","id",assessment],["api_evidence","id",evidence],
   ["api_findings","id",finding],["api_reports","id",report]
  ]){
   const row=await clone.query("SELECT count(*)::int AS n FROM "+table+" WHERE "+where+"=$1",[id]);
   assert.equal(row.rows[0].n,1,table);
  }
  const history=await clone.query("SELECT projection FROM api_reports WHERE id=$1",[report]);
  assert.deepEqual(history.rows[0].projection,{phase:5,history:"preserved"});
  const kinds=await clone.query("SELECT engine_version FROM api_assessments WHERE id=$1",[assessment]);
  assert.equal(kinds.rows[0].engine_version,"legacy-v1");
  const pt=await clone.query("SELECT count(*)::int AS n FROM api_pt_permits");
  assert.equal(pt.rows[0].n,1,"one explicitly seeded historical synthetic permit; no implicit new permission");
  const security=await clone.query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='public.api_pt_permits'::regclass");
  assert.equal(security.rows[0].relrowsecurity,true);
  assert.equal(security.rows[0].relforcerowsecurity,true);
  await assert.rejects(()=>clone.query("UPDATE api_reports SET projection='{}'::jsonb WHERE id=$1",[report]),/PHASE1_IMMUTABLE/);
  assert.equal((await clone.query("SELECT count(*)::int AS n FROM api_schema_migrations")).rows[0].n,12);
 }finally{
  await clone.end();
  if(created)await admin.query("DROP DATABASE "+name);
  await admin.end();
 }
});
