-- Phase 03: additive deterministic inventory assessment, retaining all historical Phase 0/1/2 semantics.
ALTER TABLE public.api_assessments
 ADD COLUMN engine_version text NOT NULL DEFAULT 'legacy-v1' CHECK(engine_version IN ('legacy-v1','inventory-v1')),
 ADD COLUMN inventory_version integer,
 ADD COLUMN inventory_raw_fingerprint char(64),
 ADD COLUMN inventory_fingerprint char(64),
 ADD CONSTRAINT inventory_assessment_provenance CHECK(engine_version='legacy-v1' OR
   (inventory_version IS NOT NULL AND inventory_version>0 AND inventory_raw_fingerprint IS NOT NULL AND inventory_fingerprint IS NOT NULL));
ALTER TABLE public.api_findings
 ADD COLUMN stable_fingerprint char(64),
 ADD COLUMN correlation_key char(64),
 ADD COLUMN rule_version text,
 ADD COLUMN potential_impact text,
 ADD COLUMN evidence_confidence text CHECK(evidence_confidence IN ('HIGH','MEDIUM','LOW')),
 ADD COLUMN severity text CHECK(severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL_CANDIDATE'));
ALTER TABLE public.api_rule_results
 ADD COLUMN execution_status text CHECK(execution_status IN ('EVALUATED','SKIPPED')),
 ADD COLUMN skip_reason text,
 ADD COLUMN match_count integer CHECK(match_count>=0);
CREATE UNIQUE INDEX api_phase03_unique_observation ON public.api_findings(tenant_id,assessment_id,stable_fingerprint)
 WHERE stable_fingerprint IS NOT NULL;
CREATE INDEX api_phase03_assessment_engine ON public.api_assessments(tenant_id,target_id,engine_version,created_at DESC);
CREATE INDEX api_phase03_finding_correlation ON public.api_findings(tenant_id,assessment_id,correlation_key);
-- Reports, findings and supporting evidence are irrevocable snapshots after publication.
CREATE TRIGGER immutable_assessment_report BEFORE UPDATE OR DELETE ON public.api_reports
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_assessment_finding BEFORE UPDATE OR DELETE ON public.api_findings
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_assessment_evidence BEFORE UPDATE OR DELETE ON public.api_evidence
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_rule_result BEFORE UPDATE OR DELETE ON public.api_rule_results
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
