-- Independent API Family schema. Never create Main Platform identity or commercial tables.
CREATE TABLE IF NOT EXISTS api_targets (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  base_url text NOT NULL, environment text NOT NULL CHECK (environment IN ('SYNTHETIC','STAGING','PRODUCTION')),
  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS api_specifications (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, target_id uuid NOT NULL, filename text NOT NULL,
  format text NOT NULL, fingerprint char(64) NOT NULL, raw_spec text NOT NULL CHECK (length(raw_spec) <= 1048576),
  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,id),
  FOREIGN KEY (tenant_id,target_id) REFERENCES api_targets(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS api_operations (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, specification_id uuid NOT NULL,
  operation_key text NOT NULL, method text NOT NULL, path text NOT NULL, operation_id text,
  pointer text NOT NULL, security_json jsonb, UNIQUE(tenant_id,specification_id,operation_key),
  FOREIGN KEY (tenant_id,specification_id) REFERENCES api_specifications(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS api_assessments (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, target_id uuid NOT NULL, specification_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('QUEUED','PROCESSING','COMPLETED','FAILED','CANCELLED')),
  mode text NOT NULL CHECK (mode = 'SPEC_ONLY'),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  error_code text, created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
  UNIQUE(tenant_id,id), UNIQUE(tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,target_id) REFERENCES api_targets(tenant_id,id),
  FOREIGN KEY (tenant_id,specification_id) REFERENCES api_specifications(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS api_rule_results (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, assessment_id uuid NOT NULL, rule_id text NOT NULL,
  rule_version text NOT NULL, operation_key text, coverage text NOT NULL,
  FOREIGN KEY (tenant_id,assessment_id) REFERENCES api_assessments(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS api_evidence (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, assessment_id uuid NOT NULL,
  fingerprint char(64) NOT NULL, pointer text NOT NULL, content_json jsonb NOT NULL, UNIQUE(tenant_id,id),
  FOREIGN KEY (tenant_id,assessment_id) REFERENCES api_assessments(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS api_findings (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, assessment_id uuid NOT NULL, evidence_id uuid NOT NULL,
  rule_id text NOT NULL, operation_key text, category text NOT NULL, explanation text NOT NULL,
  remediation text NOT NULL, confidence text NOT NULL CHECK (confidence = 'SPEC_OBSERVATION'),
  validation_level text NOT NULL CHECK (validation_level = 'SPEC_ONLY'),
  review_required boolean NOT NULL CHECK (review_required),
  FOREIGN KEY (tenant_id,assessment_id) REFERENCES api_assessments(tenant_id,id),
  FOREIGN KEY (tenant_id,evidence_id) REFERENCES api_evidence(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS api_reports (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, assessment_id uuid NOT NULL,
  projection jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(tenant_id,assessment_id), FOREIGN KEY (tenant_id,assessment_id) REFERENCES api_assessments(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS api_audit (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, action text NOT NULL, subject_id uuid NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);
-- Explicitly non-customer queue: worker-only; secure production role separation pending Host integration.
CREATE TABLE IF NOT EXISTS api_assessment_queue (
  assessment_id uuid PRIMARY KEY REFERENCES api_assessments(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL, claim_token uuid, locked_until timestamptz
);
-- FORCE RLS avoids table-owner bypass in the service connection.
DO $block$ DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['api_targets','api_specifications','api_operations','api_assessments','api_rule_results','api_evidence','api_findings','api_reports','api_audit']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
    EXECUTE format('DROP POLICY IF EXISTS tenant_scope ON %I',tab);
    EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id = nullif(current_setting(''api.tenant_id'', true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''api.tenant_id'', true),'''')::uuid)',tab);
  END LOOP;
END $block$;
CREATE INDEX IF NOT EXISTS api_queue_claim_idx ON api_assessment_queue (locked_until);
CREATE INDEX IF NOT EXISTS api_targets_tenant_idx ON api_targets (tenant_id,created_at);
CREATE INDEX IF NOT EXISTS api_spec_target_idx ON api_specifications (tenant_id,target_id);
CREATE INDEX IF NOT EXISTS api_findings_assessment_idx ON api_findings (tenant_id,assessment_id);
