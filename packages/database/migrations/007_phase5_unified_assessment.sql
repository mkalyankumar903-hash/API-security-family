-- Phase 05: additive read-only unified projection query indexes.
-- No existing evidence, report, schema version or historical assessment is rewritten.
CREATE INDEX IF NOT EXISTS api_phase05_history
  ON public.api_assessments (tenant_id,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS api_phase05_history_filtered
  ON public.api_assessments (tenant_id,target_id,engine_version,status,created_at DESC);
CREATE INDEX IF NOT EXISTS api_phase05_findings_filter
  ON public.api_findings (tenant_id,assessment_id,rule_id,operation_key,id);
CREATE INDEX IF NOT EXISTS api_phase05_findings_impact
  ON public.api_findings (tenant_id,assessment_id,severity,evidence_confidence);
CREATE INDEX IF NOT EXISTS api_phase05_rule_coverage
  ON public.api_rule_results (tenant_id,assessment_id,rule_id,rule_version);
-- Existing FORCE RLS and immutable triggers remain authoritative.
