-- Phase08 additive terminal-coverage authority; Phase00-07 migrations/reports unchanged.
CREATE TABLE public.api_pt8_terminal_coverage (
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 assessment_id uuid NOT NULL,
 final_status text NOT NULL CHECK(final_status IN('FAILED','CANCELLED')),
 fingerprint char(64) NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object' AND
  projection->>'schemaVersion'='pt-terminal-coverage-v1' AND
  projection->>'assessmentComplete'='false' AND
  projection->>'verifiedFixed'='false' AND projection->>'customerRuntimeVerified'='false'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt_detection_plans(tenant_id,assessment_id)
);
ALTER TABLE public.api_pt8_terminal_coverage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_pt8_terminal_coverage FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.api_pt8_terminal_coverage
 USING(tenant_id=nullif(current_setting('api.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('api.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON public.api_pt8_terminal_coverage TO api_family,api_family_queue;
CREATE TRIGGER immutable_pt8_terminal_coverage BEFORE UPDATE OR DELETE
 ON public.api_pt8_terminal_coverage FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE INDEX api_pt8_terminal_history ON public.api_pt8_terminal_coverage(tenant_id,created_at DESC,assessment_id);
