import {createHash} from "node:crypto";
import {withWorkerTenant,uuid} from "../../database/src/index.js";
import {evaluateAuthFixture, AUTH_ENGINE_VERSION, type Fixture,type Scheme} from "../../assessment-engine/src/auth-fixture.js";

/** Reuses Phase00-03 private queue and two-phase lease publication; no new job authority. */
export async function processAuthFixtureJob(tenant:string,jobId:string,token:string):Promise<void>{
 if(process.env.NODE_ENV==="production"||process.env.SYNTHETIC_AUTH_ENABLED!=="true")
  throw new Error("SYNTHETIC_FIXTURE_PRODUCTION_DENIED");
 const state=await withWorkerTenant(tenant,async tx=>{
  const r=await tx.query(
   "SELECT a.id,a.status,a.target_id,a.specification_id,a.inventory_version,a.inventory_raw_fingerprint,a.inventory_fingerprint,c.profile_id,c.profile_revision,c.fixture_version,c.target_revision,c.scope_revision,c.specification_version,c.declared_schemes,p.revision,p.scheme,p.status AS profile_status,p.validation_status,p.credential_reference,p.target_revision AS current_target_revision,p.scope_revision AS current_scope_revision,t.lifecycle,t.environment,t.revision AS target_revision_now,t.scope_revision AS target_scope_now,i.raw_fingerprint,i.normalized_fingerprint,s.fingerprint AS document_fingerprint FROM api_assessments a JOIN api_auth_assessment_configs c ON c.assessment_id=a.id AND c.tenant_id=a.tenant_id JOIN api_auth_profiles p ON p.id=c.profile_id AND p.tenant_id=a.tenant_id JOIN api_targets t ON t.id=a.target_id AND t.tenant_id=a.tenant_id JOIN api_spec_inventories i ON i.specification_id=a.specification_id AND i.tenant_id=a.tenant_id JOIN api_specifications s ON s.id=a.specification_id AND s.tenant_id=a.tenant_id WHERE a.id=$1 AND a.engine_version='auth-fixture-v1'",
   [jobId]);
  if(!r.rowCount)throw new Error("AUTH04_CONFIG_MISSING");
  const x=r.rows[0];
  if(!["PROCESSING","QUEUED"].includes(x.status)||x.lifecycle!=="ACTIVE"||x.environment!=="SYNTHETIC"||
   x.profile_status!=="ACTIVE"||x.validation_status!=="VALID"||x.revision!==x.profile_revision||
   x.target_revision_now!==x.target_revision||x.target_scope_now!==x.scope_revision||
   x.current_target_revision!==x.target_revision||x.current_scope_revision!==x.scope_revision||
   x.specification_version!==x.inventory_version||x.raw_fingerprint!==x.inventory_raw_fingerprint||
   x.normalized_fingerprint!==x.inventory_fingerprint||x.document_fingerprint!==x.raw_fingerprint)
   throw new Error("AUTH04_FIXTURE_ELIGIBILITY_STALE");
  const ref=await tx.query("SELECT 1 FROM api_target_credentials WHERE target_id=$1 AND reference=$2",[x.target_id,x.credential_reference]);
  if(!ref.rowCount)throw new Error("AUTH04_CREDENTIAL_REFERENCE_REMOVED");
  return x as {target_id:string;specification_id:string;profile_id:string;profile_revision:number;scheme:Scheme;fixture_version:Fixture;
   inventory_version:number;declared_schemes:{name:string;status:string}[];target_revision:number;scope_revision:number};
 });
 const output=await evaluateAuthFixture({tenantId:tenant,targetId:state.target_id,scheme:state.scheme,fixture:state.fixture_version,maxEvaluations:60,deadlineMs:5000});
 await withWorkerTenant(tenant,async tx=>{
  // Same queue -> assessment lock order as cancel and previous engines.
  const lease=(await tx.query("SELECT claim_token FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[jobId])).rows[0];
  if(lease?.claim_token!==token)return;
  const assessment=(await tx.query("SELECT status FROM api_assessments WHERE id=$1 AND engine_version=$2 FOR UPDATE",[jobId,AUTH_ENGINE_VERSION])).rows[0];
  if(!assessment||assessment.status!=="PROCESSING"){
   await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId,token]);return;
  }
  // Recheck authorization at publication, not only at admission. Revocation/target/scope
  // updates invalidate the in-flight result and roll back the entire transaction.
  const current=(await tx.query("SELECT p.revision,p.status,p.validation_status,p.credential_reference,t.lifecycle,t.environment,t.revision AS target_revision,t.scope_revision FROM api_auth_profiles p JOIN api_targets t ON t.id=p.target_id AND t.tenant_id=p.tenant_id WHERE p.id=$1 FOR UPDATE OF p,t",[state.profile_id])).rows[0];
  if(!current||current.revision!==state.profile_revision||current.status!=="ACTIVE"||current.validation_status!=="VALID"||
   current.lifecycle!=="ACTIVE"||current.environment!=="SYNTHETIC"||current.target_revision!==state.target_revision||
   current.scope_revision!==state.scope_revision||
   !(await tx.query("SELECT 1 FROM api_target_credentials WHERE target_id=$1 AND reference=$2",[state.target_id,current.credential_reference])).rowCount)
   throw new Error("AUTH04_PUBLICATION_AUTHORIZATION_REVOKED");
  const observations:Record<string,unknown>[]=[];
  for(const item of output.evaluations){
   const eId=uuid();
   await tx.query(
    "INSERT INTO api_auth_evaluations(id,tenant_id,assessment_id,rule_id,rule_revision,fixture_version,profile_id,profile_revision,identity_key,role_name,operation_key,expected,observed,http_status,response_bytes,outcome,fingerprint,fixture_only,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,true,$18)",
    [eId,tenant,jobId,item.ruleId,item.revision,state.fixture_version,state.profile_id,state.profile_revision,
     item.identity,item.role,item.operationKey,item.expected,item.observed,item.status,item.responseBytes,item.result,item.fingerprint,item.reason]);
   await tx.query("INSERT INTO api_rule_results(id,tenant_id,assessment_id,rule_id,rule_version,operation_key,coverage,execution_status,skip_reason,match_count) VALUES($1,$2,$3,$4,$5,$6,'SYNTHETIC_AUTH_FIXTURE','EVALUATED',NULL,$7)",
    [uuid(),tenant,jobId,item.ruleId,item.revision,item.operationKey,item.result==="DEVIATION"?1:0]);
   if(item.result!=="DEVIATION")continue;
   const evidence={
    tenantId:tenant,targetId:state.target_id,assessmentId:jobId,specificationId:state.specification_id,
    specificationVersion:state.inventory_version,fixtureVersion:state.fixture_version,
    profileId:state.profile_id,profileRevision:state.profile_revision,
    engineVersion:AUTH_ENGINE_VERSION,ruleId:item.ruleId,ruleRevision:item.revision,
    fingerprint:item.fingerprint,identity:item.identity,role:item.role,operationKey:item.operationKey,
    expected:item.expected,observed:item.observed,status:item.status,responseBytes:item.responseBytes,
    confidence:item.confidence,validationLevel:"SYNTHETIC_AUTH_FIXTURE",reason:item.reason,
    limitation:"Fixture-only observation, not evidence of any defect in the customer's real API"
   };
   const hash=createHash("sha256").update(JSON.stringify(evidence)).digest("hex");
   const evidenceId=uuid(),findingId=uuid(),pointer="/fixtures/"+state.fixture_version+"/"+item.operationKey;
   await tx.query("INSERT INTO api_evidence(id,tenant_id,assessment_id,fingerprint,pointer,content_json) VALUES($1,$2,$3,$4,$5,$6::jsonb)",
    [evidenceId,tenant,jobId,hash,pointer,JSON.stringify(evidence)]);
   const explanation="Trusted synthetic policy expected "+item.expected+" but "+state.fixture_version+" returned "+item.observed+
    " for "+item.identity+" on "+item.operationKey+". Fixture-only, never customer runtime evidence.";
   const remediation="Correct synthetic fixture authorization policy and retest; independently test the customer's real system only after Host authorization.";
   await tx.query(
    "INSERT INTO api_findings(id,tenant_id,assessment_id,evidence_id,rule_id,operation_key,category,explanation,remediation,confidence,validation_level,review_required,stable_fingerprint,correlation_key,rule_version,potential_impact,evidence_confidence,severity) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'SYNTHETIC_FIXTURE_OBSERVATION','SYNTHETIC_AUTH_FIXTURE',true,$10,$11,$12,$13,'HIGH','MEDIUM')",
    [findingId,tenant,jobId,evidenceId,item.ruleId,item.operationKey,item.ruleId.includes("AUTH")?"AUTHORIZATION":"AUTHENTICATION",
     explanation,remediation,item.fingerprint,hash,item.revision,
     "Potential synthetic cross-identity access; no customer impact established."]);
   observations.push({id:findingId,evidenceId,...evidence,explanation,remediation});
  }
  const skipped=state.declared_schemes.filter(x=>x.status==="UNSUPPORTED");
  for(const s of skipped){
   const name=String(s.name).slice(0,128);
   await tx.query("INSERT INTO api_rule_results(id,tenant_id,assessment_id,rule_id,rule_version,coverage,execution_status,skip_reason,match_count) VALUES($1,$2,$3,'AUTH04_UNSUPPORTED_DECLARATION','1','SYNTHETIC_AUTH_FIXTURE','SKIPPED',$4,0)",
    [uuid(),tenant,jobId,"UNSUPPORTED_SCHEME:"+name]);
  }
  const report={assessmentId:jobId,targetId:state.target_id,specificationId:state.specification_id,
   specificationVersion:state.inventory_version,engineVersion:AUTH_ENGINE_VERSION,analysisProfile:"SYNTHETIC_AUTH_FIXTURE",
   mode:"SPEC_ONLY",fixtureVersion:state.fixture_version,fixturePolicyVersion:"auth-policy-v1",
   profileId:state.profile_id,profileRevision:state.profile_revision,scheme:state.scheme,
   generatedAt:new Date().toISOString(),evaluationCount:output.evaluations.length,
   observationCount:observations.length,observations,coverage:{...output.coverage,unsupportedDeclaredSchemes:skipped.length,
    untestedCustomerOperations:true},declaredSchemes:state.declared_schemes,
   fixtureEvaluations:output.evaluations,confirmedCustomerVulnerabilities:[],customerNetworkRequests:0,
   runtimeValidation:false,limitations:output.limitations,
   notice:"SYNTHETIC AUTHENTICATED ASSESSMENT — NOT REAL HOST AUTHORIZATION OR CUSTOMER RUNTIME VERIFICATION."};
  await tx.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",
   [uuid(),tenant,jobId,JSON.stringify(report)]);
  await tx.query("UPDATE api_assessments SET status='COMPLETED',completed_at=now() WHERE id=$1",[jobId]);
  await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,'AUTH04_FIXTURE_COMPLETED',$3)",
   [uuid(),tenant,jobId]);
  await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId,token]);
 });
}
