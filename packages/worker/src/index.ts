import { createHash } from "node:crypto";
import { assess, parseSpec } from "../../assessment-engine/src/index.js";
import { claimJob, uuid, withTenant } from "../../database/src/index.js";

const RULES = ["SPEC_AUTH_UNDECLARED", "SPEC_SENSITIVE_UNDECLARED", "SPEC_UNKNOWN_SCHEME", "SPEC_INCONSISTENT_AUTH", "SPEC_HTTP_SERVER"];
export async function processOneJob(): Promise<boolean> {
  const lease = await claimJob();
  if (!lease) return false;
  const { tenant_id: tenant, assessment_id: jobId, claim_token: token } = lease;
  try {
    const job = await withTenant(tenant, async tx => {
      const result = await tx.query("SELECT a.id,a.status,a.target_id,a.specification_id,s.raw_spec,s.fingerprint FROM api_assessments a JOIN api_specifications s ON s.id=a.specification_id AND s.tenant_id=a.tenant_id WHERE a.id=$1", [jobId]);
      if (!result.rows[0] || !["QUEUED","PROCESSING"].includes(result.rows[0].status)) return null;
      await tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[jobId]);
      return result.rows[0] as { id:string;target_id:string;specification_id:string;raw_spec:string;fingerprint:string };
    });
    if (!job) {
      await withTenant(tenant, async tx => { await tx.query("DELETE FROM api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId, token]); });
      return true;
    }
    const spec = parseSpec(job.raw_spec);
    const observations = assess(spec);
    await withTenant(tenant, async tx => {
      const leaseCheck = await tx.query("SELECT claim_token FROM api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[jobId]);
      if (leaseCheck.rows[0]?.claim_token !== token) return;
      const state = await tx.query("SELECT status FROM api_assessments WHERE id=$1 FOR UPDATE",[jobId]);
      if (!state.rows[0] || state.rows[0].status !== "PROCESSING") {
        await tx.query("DELETE FROM api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId,token]); return;
      }
      for (const rule of RULES) {
        await tx.query("INSERT INTO api_rule_results(id,tenant_id,assessment_id,rule_id,rule_version,coverage) VALUES ($1,$2,$3,$4,$5,$6)",[uuid(),tenant,jobId,rule,"1.0.0","SPEC_ONLY"]);
      }
      const findings = [];
      for (const observation of observations) {
        const evidenceId = uuid(), findingId = uuid();
        const content = { specificationFingerprint: spec.fingerprint, pointer: observation.evidencePointer, operationKey: observation.operationKey, ruleId: observation.ruleId };
        const evidenceHash = createHash("sha256").update(JSON.stringify(content)).digest("hex");
        await tx.query("INSERT INTO api_evidence(id,tenant_id,assessment_id,fingerprint,pointer,content_json) VALUES ($1,$2,$3,$4,$5,$6::jsonb)",[evidenceId,tenant,jobId,evidenceHash,observation.evidencePointer,JSON.stringify(content)]);
        await tx.query("INSERT INTO api_findings(id,tenant_id,assessment_id,evidence_id,rule_id,operation_key,category,explanation,remediation,confidence,validation_level,review_required) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",[findingId,tenant,jobId,evidenceId,observation.ruleId,observation.operationKey,observation.category,observation.explanation,observation.remediation,observation.confidence,observation.validationLevel,observation.reviewRequired]);
        findings.push({ id: findingId, evidenceId, ...observation });
      }
      const report = {
        assessmentId: jobId, targetId: job.target_id, specificationId: job.specification_id,
        specificationFingerprint: spec.fingerprint, mode:"SPEC_ONLY", generatedAt: new Date().toISOString(),
        rulesExecuted: RULES.map(id => ({ id, version: "1.0.0" })),
        operationsAssessed: spec.operations.length, observationCount: findings.length,
        observations: findings, confirmedVulnerabilities: [],
        coverage: { level:"SPEC_ONLY", runtimeValidation:false, operationKeys:spec.operations.map(x=>x.key) },
        limitations: ["UNKNOWN != SAFE","NO EVIDENCE != SAFE","FIX APPLIED != VERIFIED_FIXED","No runtime vulnerabilities are confirmed by OpenAPI specification analysis."],
        remediation: [...new Set(findings.map(x=>x.remediation))]
      };
      await tx.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",[uuid(),tenant,jobId,JSON.stringify(report)]);
      await tx.query("UPDATE api_assessments SET status='COMPLETED',completed_at=now() WHERE id=$1",[jobId]);
      await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,$3,$4)",[uuid(),tenant,"ASSESSMENT_COMPLETED",jobId]);
      await tx.query("DELETE FROM api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId,token]);
    });
  } catch {
    // Failed work is auditable; never mark a failed assessment as successful.
    await withTenant(tenant, async tx => {
      const leaseCheck = await tx.query("SELECT claim_token FROM api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[jobId]);
      if (leaseCheck.rows[0]?.claim_token !== token) return;
      await tx.query("UPDATE api_assessments SET status='FAILED',error_code='ASSESSMENT_ENGINE_FAILURE',completed_at=now() WHERE id=$1 AND status='PROCESSING'",[jobId]);
      await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,$3,$4)",[uuid(),tenant,"ASSESSMENT_FAILED",jobId]);
      await tx.query("DELETE FROM api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[jobId,token]);
    });
  }
  return true;
}
export async function drainQueue(max = 100): Promise<number> {
  let processed = 0;
  while (processed < max && await processOneJob()) processed++;
  return processed;
}
