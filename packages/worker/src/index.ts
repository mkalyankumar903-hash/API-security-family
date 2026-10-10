import { createHash } from "node:crypto";
import { assess, parseAndValidateSpec } from "../../assessment-engine/src/index.js";
import {detectInventory} from "../../assessment-engine/src/inventory.js";
import {detectRichInventory} from "../../assessment-engine/src/rich.js";
import type {RichInventory} from "../../discovery/src/rich.js";
import {processAuthFixtureJob} from "./auth.js";
import {processPtJob} from "./pt.js";
import {processPtDetectionJob} from "./pt-detection.js";
import {processPtOrchestrationJob} from "./pt-orchestrator.js";
import {scheduleConservativeRetry} from "./safety-retry.js";
import type {Inventory} from "../../discovery/src/index.js";
import { claimJob,renewWorkerClaim,finishWorkerAttempt,releaseUnstartedWorkerClaim, uuid, withWorkerTenant } from "../../database/src/index.js";

const RULES = ["SPEC_AUTH_UNDECLARED", "SPEC_SENSITIVE_UNDECLARED", "SPEC_UNKNOWN_SCHEME", "SPEC_INCONSISTENT_AUTH", "SPEC_HTTP_SERVER"];
export async function processOneJob(options:{signal?:AbortSignal}={}): Promise<boolean> {
  if(options.signal?.aborted)return false;
  const lease = await claimJob();
  if (!lease) return false;
  const { tenant_id: tenant, assessment_id: jobId, claim_token: token } = lease;
  if(options.signal?.aborted){
    await releaseUnstartedWorkerClaim(lease);
    return true;
  }
  // DB-authoritative heartbeats only maintain an existing lease. If renewal fails,
  // every governed evaluation/publication boundary still rechecks the private claim.
  let heartbeatInFlight:Promise<void>|null=null;
  let leaseLost=false;
  const heartbeat=setInterval(()=>{
    if(heartbeatInFlight||leaseLost)return;
    heartbeatInFlight=renewWorkerClaim(lease).then(ok=>{if(!ok)leaseLost=true;})
      .catch(()=>{leaseLost=true;})
      .finally(()=>{heartbeatInFlight=null;});
  },10000);
  heartbeat.unref();
  try {
    if(options.signal?.aborted){
      await releaseUnstartedWorkerClaim(lease);
      return true;
    }
    const job = await withWorkerTenant(tenant, async tx => {
      const result = await tx.query("SELECT a.id,a.status,a.target_id,a.specification_id,a.engine_version,a.inventory_version,a.inventory_fingerprint,a.inventory_raw_fingerprint,i.snapshot,s.raw_spec,s.fingerprint,r.snapshot AS rich_snapshot,r.rich_fingerprint FROM api_assessments a JOIN api_specifications s ON s.id=a.specification_id AND s.tenant_id=a.tenant_id LEFT JOIN api_spec_inventories i ON i.specification_id=a.specification_id AND i.tenant_id=a.tenant_id LEFT JOIN api_rich_inventories r ON r.specification_id=a.specification_id AND r.tenant_id=a.tenant_id WHERE a.id=$1", [jobId]);
      if (!result.rows[0] || !["QUEUED","PROCESSING"].includes(result.rows[0].status)) return null;
      await tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[jobId]);
      return result.rows[0] as { id:string;target_id:string;specification_id:string;raw_spec:string;fingerprint:string;engine_version:string;inventory_version:number|null;inventory_fingerprint:string|null;inventory_raw_fingerprint:string|null;snapshot:Inventory|null;rich_snapshot:RichInventory|null;rich_fingerprint:string|null };
    });
    if (!job) {
      await withWorkerTenant(tenant, async tx => { await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId, token]); });
      return true;
    }
    if(options.signal?.aborted||leaseLost){
      // We have not begun any execution in this attempt. Retry on a new claim.
      await releaseUnstartedWorkerClaim(lease);
      return true;
    }
    if(!["legacy-v1","inventory-v1","inventory-v2","auth-fixture-v1",
      "pt-fixture-v1","pt-detection-v1","pt-orchestrator-v1"].includes(job.engine_version)){
      throw new Error("UNSUPPORTED_WORKER_ENGINE");
    }
    if(job.engine_version==="pt-orchestrator-v1"){
      await processPtOrchestrationJob(tenant,jobId,token);
      return true;
    }
    if(job.engine_version==="pt-detection-v1"){
      await processPtDetectionJob(tenant,jobId,token);
      return true;
    }
    if(job.engine_version==="pt-fixture-v1"){
      await processPtJob(tenant,jobId,token);
      return true;
    }
    if(job.engine_version==="auth-fixture-v1"){
      await processAuthFixtureJob(tenant,jobId,token);
      return true;
    }
    const richBased=job.engine_version==="inventory-v2";
    const inventoryBased=job.engine_version==="inventory-v1"||richBased;
    if(inventoryBased&&(!job.snapshot||job.inventory_fingerprint!==job.snapshot.normalizedFingerprint||
      job.inventory_raw_fingerprint!==job.snapshot.rawFingerprint||job.fingerprint!==job.snapshot.rawFingerprint))
      throw new Error("INVENTORY_SNAPSHOT_MISMATCH");
    const detected=richBased?(job.rich_snapshot&&job.rich_fingerprint===job.rich_snapshot.richFingerprint?
       detectRichInventory(job.snapshot!,job.rich_snapshot):(()=>{throw new Error("RICH_INVENTORY_MISSING_OR_TAMPERED");})()):
      inventoryBased?detectInventory(job.snapshot!):null;
    const spec=inventoryBased?null:await parseAndValidateSpec(job.raw_spec);
    const observations=spec?assess(spec):[];
    await withWorkerTenant(tenant, async tx => {
      const leaseCheck = await tx.query("SELECT claim_token,claim_generation,locked_until>clock_timestamp() AS lease_valid FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[jobId]);
      if (leaseCheck.rows[0]?.claim_token !== token ||
        Number(leaseCheck.rows[0]?.claim_generation)!==lease.claim_generation ||
        leaseCheck.rows[0]?.lease_valid!==true) return;
      const state = await tx.query("SELECT status FROM api_assessments WHERE id=$1 FOR UPDATE",[jobId]);
      if (!state.rows[0] || state.rows[0].status !== "PROCESSING") {
        await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId,token]); return;
      }
      if(detected){
        const findings=[];
        for(const result of detected.coverage){
          await tx.query("INSERT INTO api_rule_results(id,tenant_id,assessment_id,rule_id,rule_version,coverage,execution_status,skip_reason,match_count) VALUES($1,$2,$3,$4,$5,'SPEC_ONLY',$6,$7,$8)",
            [uuid(),tenant,jobId,result.ruleId,result.revision,result.status,result.reason,result.matches]);
        }
        for(const observation of detected.observations){
          const evidenceId=uuid(),findingId=uuid();
          const evidenceHash=createHash("sha256").update(JSON.stringify(observation.evidence)).digest("hex");
          await tx.query("INSERT INTO api_evidence(id,tenant_id,assessment_id,fingerprint,pointer,content_json) VALUES($1,$2,$3,$4,$5,$6::jsonb)",
            [evidenceId,tenant,jobId,evidenceHash,observation.pointer,JSON.stringify(observation.evidence)]);
          await tx.query("INSERT INTO api_findings(id,tenant_id,assessment_id,evidence_id,rule_id,operation_key,category,explanation,remediation,confidence,validation_level,review_required,stable_fingerprint,correlation_key,rule_version,potential_impact,evidence_confidence,severity) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'SPEC_OBSERVATION','SPEC_ONLY',true,$10,$11,$12,$13,$14,$15)",
            [findingId,tenant,jobId,evidenceId,observation.ruleId,observation.operationKey,observation.category,observation.explanation,observation.remediation,
             observation.fingerprint,observation.correlationKey,observation.ruleRevision,observation.potentialImpact,observation.confidence,observation.impact]);
          findings.push({id:findingId,evidenceId,...observation});
        }
        const report={assessmentId:jobId,targetId:job.target_id,specificationId:job.specification_id,specificationVersion:job.inventory_version,
          rawFingerprint:detected.rawFingerprint,normalizedFingerprint:detected.normalizedFingerprint,engineVersion:detected.engineVersion,
          canonicalVersion:detected.canonicalVersion,richFingerprint:richBased?job.rich_fingerprint:null,mode:"SPEC_ONLY",generatedAt:new Date().toISOString(),
          observationCount:findings.length,operationsAssessed:job.snapshot!.operations.length,
          observations:findings,coverage:detected.coverage,warnings:detected.warnings,
          confirmedVulnerabilities:[],runtimeValidation:false,limitations:detected.limitations};
        await tx.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",
          [uuid(),tenant,jobId,JSON.stringify(report)]);
        await tx.query("UPDATE api_assessments SET status='COMPLETED',completed_at=now() WHERE id=$1",[jobId]);
        await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,'ASSESSMENT_COMPLETED',$3)",[uuid(),tenant,jobId]);
        await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId,token]);
        return;
      }
      for (const rule of RULES) {
        await tx.query("INSERT INTO api_rule_results(id,tenant_id,assessment_id,rule_id,rule_version,coverage) VALUES ($1,$2,$3,$4,$5,$6)",[uuid(),tenant,jobId,rule,"1.0.0","SPEC_ONLY"]);
      }
      const findings = [];
      for (const observation of observations) {
        const evidenceId = uuid(), findingId = uuid();
        const content = { specificationFingerprint: spec!.fingerprint, pointer: observation.evidencePointer, operationKey: observation.operationKey, ruleId: observation.ruleId };
        const evidenceHash = createHash("sha256").update(JSON.stringify(content)).digest("hex");
        await tx.query("INSERT INTO api_evidence(id,tenant_id,assessment_id,fingerprint,pointer,content_json) VALUES ($1,$2,$3,$4,$5,$6::jsonb)",[evidenceId,tenant,jobId,evidenceHash,observation.evidencePointer,JSON.stringify(content)]);
        await tx.query("INSERT INTO api_findings(id,tenant_id,assessment_id,evidence_id,rule_id,operation_key,category,explanation,remediation,confidence,validation_level,review_required) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",[findingId,tenant,jobId,evidenceId,observation.ruleId,observation.operationKey,observation.category,observation.explanation,observation.remediation,observation.confidence,observation.validationLevel,observation.reviewRequired]);
        findings.push({ id: findingId, evidenceId, ...observation });
      }
      const report = {
        assessmentId: jobId, targetId: job.target_id, specificationId: job.specification_id,
        specificationFingerprint: spec!.fingerprint, mode:"SPEC_ONLY", generatedAt: new Date().toISOString(),
        rulesExecuted: RULES.map(id => ({ id, version: "1.0.0" })),
        operationsAssessed: spec!.operations.length, observationCount: findings.length,
        observations: findings, confirmedVulnerabilities: [],
        coverage: { level:"SPEC_ONLY", runtimeValidation:false, operationKeys:spec!.operations.map(x=>x.key) },
        limitations: ["UNKNOWN != SAFE","NO EVIDENCE != SAFE","FIX APPLIED != VERIFIED_FIXED","No runtime vulnerabilities are confirmed by OpenAPI specification analysis."],
        remediation: [...new Set(findings.map(x=>x.remediation))]
      };
      await tx.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",[uuid(),tenant,jobId,JSON.stringify(report)]);
      await tx.query("UPDATE api_assessments SET status='COMPLETED',completed_at=now() WHERE id=$1",[jobId]);
      await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,$3,$4)",[uuid(),tenant,"ASSESSMENT_COMPLETED",jobId]);
      await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId,token]);
    });
  } catch (error) {
    const reason=error instanceof Error?error.message:"UNKNOWN_WORKER_FAILURE";
    const poison=["INVENTORY_SNAPSHOT_MISMATCH","RICH_INVENTORY_MISSING_OR_TAMPERED","UNSUPPORTED_WORKER_ENGINE"].includes(reason)?
      reason:null;
    const disposition=await scheduleConservativeRetry(lease,error).catch(()=>"NOT_RETRYABLE" as const);
    if(disposition==="RETRY_SCHEDULED"||disposition==="RETRY_EXHAUSTED")return true;
    // Failed work is auditable; never mark a failed assessment as successful.
    await withWorkerTenant(tenant, async tx => {
      const leaseCheck = await tx.query("SELECT claim_token,claim_generation,locked_until>clock_timestamp() AS lease_valid FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[jobId]);
      if (leaseCheck.rows[0]?.claim_token !== token ||
        Number(leaseCheck.rows[0]?.claim_generation)!==lease.claim_generation ||
        leaseCheck.rows[0]?.lease_valid!==true) return;
      await tx.query("UPDATE api_assessments SET status='FAILED',error_code='ASSESSMENT_ENGINE_FAILURE',completed_at=now() WHERE id=$1 AND status='PROCESSING'",[jobId]);
      await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,$3,$4)",[uuid(),tenant,"ASSESSMENT_FAILED",jobId]);
      if(poison){
        await tx.query("INSERT INTO api_worker_quarantine(assessment_id,tenant_id,reason_code,attempts) VALUES($1,$2,$3,1) ON CONFLICT DO NOTHING",
         [jobId,tenant,poison]);
        await tx.query("INSERT INTO api_worker_events(id,tenant_id,assessment_id,attempt_id,kind,code) VALUES($1,$2,$3,$4,'QUARANTINED',$5)",
         [uuid(),tenant,jobId,lease.attempt_id,poison]);
      }
      await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId,token]);
    });
  } finally {
    clearInterval(heartbeat);
    if(heartbeatInFlight)await heartbeatInFlight;
    // Finalize from durable database state. A stale worker cannot mark the newer
    // generation's attempt successful.
    await finishWorkerAttempt(lease);
  }
  return true;
}
export async function drainQueue(max = 100): Promise<number> {
  let processed = 0;
  while (processed < max && await processOneJob()) processed++;
  return processed;
}
