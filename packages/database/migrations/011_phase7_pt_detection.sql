-- Phase 07: additive isolated synthetic detection; migrations 001-010 stay immutable.
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_engine_version_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_engine_version_check
 CHECK(engine_version IN('legacy-v1','inventory-v1','auth-fixture-v1','inventory-v2','pt-fixture-v1','pt-detection-v1'));
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_mode_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_mode_check
 CHECK((mode='SPEC_ONLY' AND engine_version NOT IN('pt-fixture-v1','pt-detection-v1'))
 OR (mode='SYNTHETIC_PT_FIXTURE' AND engine_version IN('pt-fixture-v1','pt-detection-v1')));
ALTER TABLE public.api_pt_scopes DROP CONSTRAINT api_pt_scopes_fixture_id_check;
ALTER TABLE public.api_pt_scopes ADD CONSTRAINT api_pt_scopes_fixture_id_check
 CHECK(fixture_id IN('billing-safe-v1','pt-security-v1'));

CREATE TABLE public.api_pt_detection_plans(
 assessment_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 fixture_version integer NOT NULL CHECK(fixture_version=1),
 fixture_profile text NOT NULL CHECK(fixture_profile IN('SECURE_BASELINE','MISSING_AUTH_ENFORCEMENT',
  'CROSS_USER_ACCESS_WEAKNESS','ROLE_RESTRICTION_WEAKNESS','SENSITIVE_RESPONSE_EXPOSURE','INSECURE_CACHE_POLICY')),
 engine_version text NOT NULL CHECK(engine_version='pt-detection-v1'),
 rules jsonb NOT NULL CHECK(jsonb_typeof(rules)='array' AND jsonb_array_length(rules) BETWEEN 1 AND 8),
 evaluations jsonb NOT NULL CHECK(jsonb_typeof(evaluations)='array' AND jsonb_array_length(evaluations) BETWEEN 1 AND 20),
 plan_fingerprint char(64) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt_jobs(tenant_id,assessment_id)
);
CREATE TABLE public.api_pt_detection_evaluations(
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 assessment_id uuid NOT NULL,
 permit_id uuid NOT NULL,
 evaluation_key text NOT NULL CHECK(length(evaluation_key) BETWEEN 1 AND 128),
 operation_key text NOT NULL,
 method text NOT NULL CHECK(method IN('GET','HEAD')),
 path text NOT NULL,
 actor text NOT NULL CHECK(actor IN('anonymous','alice','bob','admin','invalid','expired','revoked')),
 state text NOT NULL CHECK(state IN('RESERVED','CONSUMED','UNCERTAIN')),
 evidence jsonb CHECK(evidence IS NULL OR jsonb_typeof(evidence)='object'),
 reason text,
 created_at timestamptz NOT NULL DEFAULT now(),
 settled_at timestamptz,
 UNIQUE(tenant_id,assessment_id,evaluation_key),
 UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt_detection_plans(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,permit_id) REFERENCES public.api_pt_permits(tenant_id,id),
 CHECK((state='RESERVED' AND settled_at IS NULL AND evidence IS NULL)
 OR (state IN('CONSUMED','UNCERTAIN') AND settled_at IS NOT NULL))
);
CREATE TABLE public.api_pt_detection_results(
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 assessment_id uuid NOT NULL,
 rule_id text NOT NULL,
 rule_revision text NOT NULL CHECK(rule_revision='1.0.0'),
 status text NOT NULL CHECK(status IN('PASS','OBSERVED','INCONCLUSIVE','SKIPPED')),
 code text NOT NULL,
 fingerprint char(64),
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='array'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id,rule_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt_detection_plans(tenant_id,assessment_id),
 CHECK((status='OBSERVED' AND fingerprint IS NOT NULL) OR (status<>'OBSERVED' AND fingerprint IS NULL))
);
CREATE TABLE public.api_pt_detection_reports(
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 assessment_id uuid NOT NULL,
 projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt_detection_plans(tenant_id,assessment_id)
);
DO $rls$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_pt_detection_plans','api_pt_detection_evaluations',
  'api_pt_detection_results','api_pt_detection_reports'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING(tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',tab);
 END LOOP;
END $rls$;
GRANT SELECT ON public.api_pt_detection_plans,public.api_pt_detection_evaluations,
 public.api_pt_detection_results,public.api_pt_detection_reports TO api_family;
GRANT SELECT,INSERT ON public.api_pt_detection_plans,public.api_pt_detection_results,
 public.api_pt_detection_reports TO api_family_queue;
GRANT SELECT,INSERT,UPDATE(state,evidence,reason,settled_at) ON public.api_pt_detection_evaluations TO api_family_queue;
GRANT SELECT,INSERT ON public.api_pt_detection_plans TO api_family;
CREATE TRIGGER immutable_pt7_plan BEFORE UPDATE OR DELETE ON public.api_pt_detection_plans
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_pt7_result BEFORE UPDATE OR DELETE ON public.api_pt_detection_results
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_pt7_report BEFORE UPDATE OR DELETE ON public.api_pt_detection_reports
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE OR REPLACE FUNCTION public.api_pt7_evaluation_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.state <> 'RESERVED' OR NEW.state NOT IN('CONSUMED','UNCERTAIN') OR
 NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
 NEW.assessment_id IS DISTINCT FROM OLD.assessment_id OR NEW.permit_id IS DISTINCT FROM OLD.permit_id OR
 NEW.evaluation_key IS DISTINCT FROM OLD.evaluation_key OR NEW.operation_key IS DISTINCT FROM OLD.operation_key OR
 NEW.method IS DISTINCT FROM OLD.method OR NEW.path IS DISTINCT FROM OLD.path OR
 NEW.actor IS DISTINCT FROM OLD.actor OR NEW.created_at IS DISTINCT FROM OLD.created_at
 THEN RAISE EXCEPTION 'PT7_EVALUATION_IMMUTABLE' USING ERRCODE='42501'; END IF;
 IF NEW.state='UNCERTAIN' AND NEW.evidence IS NOT NULL THEN
  RAISE EXCEPTION 'PT7_UNCERTAIN_CANNOT_HAVE_EVIDENCE' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_pt7_evaluation BEFORE UPDATE ON public.api_pt_detection_evaluations
 FOR EACH ROW EXECUTE FUNCTION public.api_pt7_evaluation_guard();
CREATE TRIGGER no_pt7_evaluation_delete BEFORE DELETE ON public.api_pt_detection_evaluations
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE INDEX api_pt7_job_history ON public.api_pt_detection_plans(tenant_id,created_at DESC,assessment_id);
CREATE INDEX api_pt7_rule_result_history ON public.api_pt_detection_results(tenant_id,rule_id,fingerprint);
CREATE INDEX api_pt7_evaluation_history ON public.api_pt_detection_evaluations(tenant_id,assessment_id,evaluation_key);
