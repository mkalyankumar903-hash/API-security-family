-- Phase 06: synthetic-only penetration-testing admission and execution evidence.
-- Forward-only extension. Earlier assessments and all migrations 001-008 remain untouched.
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_engine_version_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_engine_version_check
 CHECK (engine_version IN ('legacy-v1','inventory-v1','auth-fixture-v1','inventory-v2','pt-fixture-v1'));
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_mode_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_mode_check
 CHECK ((mode='SPEC_ONLY' AND engine_version<>'pt-fixture-v1') OR
        (mode='SYNTHETIC_PT_FIXTURE' AND engine_version='pt-fixture-v1'));

CREATE TABLE public.api_pt_scopes (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, target_id uuid NOT NULL,
 specification_id uuid NOT NULL, specification_version integer NOT NULL CHECK(specification_version>0),
 spec_fingerprint char(64) NOT NULL, target_verification_version integer NOT NULL,
 target_scope_revision integer NOT NULL, environment text NOT NULL CHECK(environment='SYNTHETIC'),
 fixture_id text NOT NULL CHECK(fixture_id='billing-safe-v1'),
 profile text NOT NULL CHECK(profile='SYNTHETIC_PT_READ_ONLY'),
 operation_keys jsonb NOT NULL CHECK(jsonb_typeof(operation_keys)='array' AND jsonb_array_length(operation_keys) BETWEEN 1 AND 20),
 exclusions jsonb NOT NULL CHECK(jsonb_typeof(exclusions)='array' AND jsonb_array_length(exclusions)<=20),
 max_evaluations integer NOT NULL CHECK(max_evaluations BETWEEN 1 AND 30),
 max_concurrency integer NOT NULL CHECK(max_concurrency BETWEEN 1 AND 2),
 rate_per_minute integer NOT NULL CHECK(rate_per_minute BETWEEN 1 AND 20),
 deadline_ms integer NOT NULL CHECK(deadline_ms BETWEEN 1000 AND 30000),
 validity_minutes integer NOT NULL CHECK(validity_minutes BETWEEN 1 AND 15),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,target_id,idempotency_key),
 FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id),
 FOREIGN KEY(tenant_id,specification_id) REFERENCES public.api_spec_inventories(tenant_id,specification_id)
);
CREATE TABLE public.api_pt_requests (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,scope_id uuid NOT NULL,
 request_fingerprint char(64) NOT NULL,requested_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,scope_id),FOREIGN KEY(tenant_id,scope_id) REFERENCES public.api_pt_scopes(tenant_id,id)
);
CREATE TABLE public.api_pt_permits (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,scope_id uuid NOT NULL,
 signed_token text NOT NULL CHECK(length(signed_token)<8192),
 token_hash char(64) NOT NULL,claims jsonb NOT NULL CHECK(jsonb_typeof(claims)='object'),
 issued_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 consumed integer NOT NULL DEFAULT 0 CHECK(consumed>=0),
 reserved integer NOT NULL DEFAULT 0 CHECK(reserved>=0),
 rate_start timestamptz NOT NULL DEFAULT now(),rate_used integer NOT NULL DEFAULT 0 CHECK(rate_used>=0),
 UNIQUE(tenant_id,id),UNIQUE(tenant_id,scope_id),UNIQUE(tenant_id,token_hash),
 FOREIGN KEY(tenant_id,scope_id) REFERENCES public.api_pt_scopes(tenant_id,id),
 CHECK(expires_at>issued_at)
);
CREATE TABLE public.api_pt_stop (
 tenant_id uuid PRIMARY KEY,enabled boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT now(),generation integer NOT NULL DEFAULT 1 CHECK(generation>=1)
);
CREATE TABLE public.api_pt_jobs (
 assessment_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,
 scope_id uuid NOT NULL,permit_id uuid NOT NULL,
 operation_keys jsonb NOT NULL CHECK(jsonb_typeof(operation_keys)='array'),
 job_deadline timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_assessments(tenant_id,id),
 FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id),
 FOREIGN KEY(tenant_id,scope_id) REFERENCES public.api_pt_scopes(tenant_id,id),
 FOREIGN KEY(tenant_id,permit_id) REFERENCES public.api_pt_permits(tenant_id,id)
);
CREATE TABLE public.api_pt_ledger (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,assessment_id uuid NOT NULL,
 permit_id uuid NOT NULL,operation_key text NOT NULL,
 state text NOT NULL CHECK(state IN('RESERVED','CONSUMED','UNCERTAIN')),
 created_at timestamptz NOT NULL DEFAULT now(),settled_at timestamptz,
 UNIQUE(tenant_id,assessment_id,operation_key),UNIQUE(tenant_id,assessment_id,evaluation_sequence),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt_jobs(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,permit_id) REFERENCES public.api_pt_permits(tenant_id,id)
);
CREATE TABLE public.api_pt_receipts (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,assessment_id uuid NOT NULL,
 permit_id uuid NOT NULL,operation_key text NOT NULL,method text NOT NULL,
 path text NOT NULL,fixture_id text NOT NULL,
 specification_version integer NOT NULL CHECK(specification_version>0),
 scope_revision integer NOT NULL CHECK(scope_revision>=0),
 permit_hash char(64) NOT NULL,
 evaluation_sequence integer NOT NULL CHECK(evaluation_sequence>0),
 budget_remaining integer NOT NULL CHECK(budget_remaining>=0),
 decision text NOT NULL CHECK(decision IN('ALLOWED','DENIED','SKIPPED')),
 outcome text NOT NULL,code text NOT NULL,
 http_status integer,response_bytes integer CHECK(response_bytes>=0 AND response_bytes<=2048),
 response_hash char(64),duration_ms integer CHECK(duration_ms>=0),
 budget_consumed integer NOT NULL CHECK(budget_consumed>=0),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id,operation_key),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt_jobs(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,permit_id) REFERENCES public.api_pt_permits(tenant_id,id)
);
CREATE TABLE public.api_pt_reports(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,assessment_id uuid NOT NULL,
 projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_pt_jobs(tenant_id,assessment_id)
);
CREATE TABLE public.api_pt_events(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,subject_id uuid NOT NULL,
 action text NOT NULL,details jsonb NOT NULL DEFAULT '{}'::jsonb,
 occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.api_pt_denials(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,scope_id uuid,
 code text NOT NULL,subject_id uuid,occurred_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,scope_id) REFERENCES public.api_pt_scopes(tenant_id,id)
);
DO $rls$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_pt_scopes','api_pt_requests','api_pt_permits','api_pt_stop','api_pt_jobs','api_pt_ledger','api_pt_receipts','api_pt_reports','api_pt_events','api_pt_denials'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING(tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',tab);
 END LOOP;
END $rls$;
GRANT SELECT,INSERT ON public.api_pt_scopes,public.api_pt_requests,public.api_pt_permits,
 public.api_pt_jobs,public.api_pt_events,public.api_pt_denials,public.api_pt_stop TO api_family;
GRANT UPDATE(revoked_at,consumed,reserved,rate_start,rate_used) ON public.api_pt_permits TO api_family;
GRANT UPDATE(enabled,updated_at,generation) ON public.api_pt_stop TO api_family;
GRANT SELECT ON public.api_pt_receipts,public.api_pt_reports,public.api_pt_ledger TO api_family;
GRANT SELECT ON public.api_inventory_operations TO api_family_queue;
GRANT SELECT,INSERT,UPDATE ON public.api_pt_scopes,public.api_pt_requests,public.api_pt_permits,
 public.api_pt_stop,public.api_pt_jobs,public.api_pt_ledger,public.api_pt_receipts,
 public.api_pt_reports,public.api_pt_events,public.api_pt_denials TO api_family_queue;
CREATE TRIGGER immutable_pt_scope BEFORE UPDATE OR DELETE ON public.api_pt_scopes
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
DO $immutable$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_pt_requests','api_pt_receipts','api_pt_reports','api_pt_events','api_pt_denials'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit()','immutable_'||tab,tab);
 END LOOP;
END $immutable$;
CREATE OR REPLACE FUNCTION public.api_pt_permit_content_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
 NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.signed_token IS DISTINCT FROM OLD.signed_token OR
 NEW.token_hash IS DISTINCT FROM OLD.token_hash OR NEW.claims IS DISTINCT FROM OLD.claims OR
 NEW.issued_at IS DISTINCT FROM OLD.issued_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
 NEW.consumed + NEW.reserved > (NEW.claims->>'maxEvaluations')::integer OR
 NEW.consumed < OLD.consumed OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at AND OLD.revoked_at IS NOT NULL
 THEN RAISE EXCEPTION 'PT_PERMIT_IMMUTABLE_OR_BUDGET' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_pt_permit BEFORE UPDATE ON public.api_pt_permits
 FOR EACH ROW EXECUTE FUNCTION public.api_pt_permit_content_guard();
CREATE TRIGGER no_pt_permit_delete BEFORE DELETE ON public.api_pt_permits
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE INDEX api_pt_scope_history ON public.api_pt_scopes(tenant_id,target_id,created_at DESC);
CREATE INDEX api_pt_jobs_scope ON public.api_pt_jobs(tenant_id,scope_id,created_at DESC);
CREATE INDEX api_pt_receipt_history ON public.api_pt_receipts(tenant_id,assessment_id,created_at);
CREATE INDEX api_pt_events_subject ON public.api_pt_events(tenant_id,subject_id,occurred_at DESC);
