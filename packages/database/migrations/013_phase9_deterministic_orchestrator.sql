-- Phase09: versioned deterministic synthetic orchestration checkpoints.
-- No mutation of accepted migration 001-012 or existing permit ledger.
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_engine_version_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_engine_version_check
 CHECK(engine_version IN('legacy-v1','inventory-v1','auth-fixture-v1','inventory-v2','pt-fixture-v1','pt-detection-v1','pt-orchestrator-v1'));
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_mode_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_mode_check
 CHECK((mode='SPEC_ONLY' AND engine_version NOT IN('pt-fixture-v1','pt-detection-v1','pt-orchestrator-v1'))
 OR (mode='SYNTHETIC_PT_FIXTURE' AND engine_version IN('pt-fixture-v1','pt-detection-v1','pt-orchestrator-v1')));

CREATE TABLE public.api_pt9_plans(
 assessment_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,policy_id text NOT NULL,
 policy_version text NOT NULL,plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object' AND
  plan->>'schemaVersion'='pt-orchestrator-plan-v1' AND plan->>'syntheticOnly'='true'),
 fingerprint char(64) NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt_jobs(tenant_id,assessment_id)
);
CREATE TABLE public.api_pt9_stages(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,assessment_id uuid NOT NULL,
 stage_id text NOT NULL CHECK(length(stage_id) BETWEEN 1 AND 48),
 stage_type text NOT NULL CHECK(stage_type IN('PREFLIGHT','AUTHENTICATION','AUTHORIZATION','RESPONSE','RECONCILIATION','FINALIZATION')),
 ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 5),
 dependencies jsonb NOT NULL CHECK(jsonb_typeof(dependencies)='array'),
 evaluation_keys jsonb NOT NULL CHECK(jsonb_typeof(evaluation_keys)='array'),
 planned integer NOT NULL CHECK(planned BETWEEN 0 AND 20),
 status text NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','RUNNING','COMPLETED','BLOCKED','FAILED','CANCELLED')),
 claim_token uuid,
 evidence_fingerprint char(64),reason text,
 started_at timestamptz,finished_at timestamptz,
 UNIQUE(tenant_id,assessment_id,stage_id),UNIQUE(tenant_id,assessment_id,ordinal),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt9_plans(tenant_id,assessment_id),
 CHECK(status <> 'COMPLETED' OR (started_at IS NOT NULL AND finished_at IS NOT NULL AND evidence_fingerprint IS NOT NULL))
);
CREATE TABLE public.api_pt9_decisions(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,assessment_id uuid NOT NULL,
 stage_id text NOT NULL,code text NOT NULL,details jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,assessment_id,stage_id) REFERENCES public.api_pt9_stages(tenant_id,assessment_id,stage_id)
);
CREATE TABLE public.api_pt9_reports(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,assessment_id uuid NOT NULL,
 projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object' AND
  projection->>'syntheticOnly'='true' AND projection->>'verifiedFixed'='false' AND
  projection->>'customerRuntimeVerified'='false'),
 fingerprint char(64) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt9_plans(tenant_id,assessment_id)
);
CREATE TABLE public.api_pt9_terminal(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,assessment_id uuid NOT NULL,
 status text NOT NULL CHECK(status IN('FAILED','CANCELLED')),
 code text NOT NULL,projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object'),
 fingerprint char(64) NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt9_plans(tenant_id,assessment_id)
);
DO $rls$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_pt9_plans','api_pt9_stages','api_pt9_decisions','api_pt9_reports','api_pt9_terminal'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING(tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',tab);
 END LOOP;
END $rls$;
GRANT SELECT ON public.api_pt9_plans,public.api_pt9_stages,public.api_pt9_decisions,
 public.api_pt9_reports,public.api_pt9_terminal TO api_family,api_family_queue;
GRANT INSERT ON public.api_pt9_plans,public.api_pt9_stages TO api_family;
GRANT INSERT ON public.api_pt9_decisions,public.api_pt9_reports,public.api_pt9_terminal TO api_family_queue;
GRANT UPDATE(status,claim_token,evidence_fingerprint,reason,started_at,finished_at) ON public.api_pt9_stages TO api_family_queue;
CREATE TRIGGER immutable_pt9_plan BEFORE UPDATE OR DELETE ON public.api_pt9_plans
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_pt9_decision BEFORE UPDATE OR DELETE ON public.api_pt9_decisions
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_pt9_report BEFORE UPDATE OR DELETE ON public.api_pt9_reports
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_pt9_terminal BEFORE UPDATE OR DELETE ON public.api_pt9_terminal
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE OR REPLACE FUNCTION public.api_pt9_stage_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
 NEW.assessment_id IS DISTINCT FROM OLD.assessment_id OR NEW.stage_id IS DISTINCT FROM OLD.stage_id OR
 NEW.stage_type IS DISTINCT FROM OLD.stage_type OR NEW.ordinal IS DISTINCT FROM OLD.ordinal OR
 NEW.dependencies IS DISTINCT FROM OLD.dependencies OR NEW.evaluation_keys IS DISTINCT FROM OLD.evaluation_keys OR
 NEW.planned IS DISTINCT FROM OLD.planned OR
 NOT ((OLD.status='PENDING' AND NEW.status='RUNNING') OR
      (OLD.status='RUNNING' AND NEW.status IN('RUNNING','COMPLETED','FAILED','CANCELLED')) OR
      (OLD.status='PENDING' AND NEW.status IN('BLOCKED','FAILED','CANCELLED')))
 THEN RAISE EXCEPTION 'PT9_STAGE_TRANSITION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_pt9_stage BEFORE UPDATE ON public.api_pt9_stages
 FOR EACH ROW EXECUTE FUNCTION public.api_pt9_stage_guard();
CREATE TRIGGER immutable_pt9_stage_delete BEFORE DELETE ON public.api_pt9_stages
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE INDEX api_pt9_stage_progress ON public.api_pt9_stages(tenant_id,assessment_id,ordinal);
CREATE INDEX api_pt9_history ON public.api_pt9_plans(tenant_id,created_at DESC,assessment_id);
