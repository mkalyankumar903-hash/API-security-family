-- Phase 1 / forward-only target onboarding migration; original Phase 0 tables and observations retained.
ALTER TABLE public.api_targets
 ADD COLUMN IF NOT EXISTS registration_key text,
 ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 1 CHECK (revision>=1),
 ADD COLUMN IF NOT EXISTS verification_version integer NOT NULL DEFAULT 1 CHECK (verification_version>=1),
 ADD COLUMN IF NOT EXISTS scope_revision integer NOT NULL DEFAULT 0 CHECK (scope_revision>=0),
 ADD COLUMN IF NOT EXISTS lifecycle text NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle IN ('ACTIVE','SUSPENDED','REVOKED','ARCHIVED')),
 ADD COLUMN IF NOT EXISTS ownership_status text NOT NULL DEFAULT 'PENDING_HOST_VERIFICATION'
    CHECK (ownership_status IN ('PENDING_HOST_VERIFICATION','SYNTHETIC_VERIFIED_TEST_ONLY')),
 ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now(),
 ADD COLUMN IF NOT EXISTS archived_at timestamptz;
-- Historical records remain explicitly unverified. No automatic legacy authorization.
UPDATE public.api_targets SET ownership_status='PENDING_HOST_VERIFICATION' WHERE ownership_status IS DISTINCT FROM 'PENDING_HOST_VERIFICATION';

CREATE TABLE public.api_target_scopes (
  id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,
  revision integer NOT NULL CHECK(revision>=1),
  proposal jsonb NOT NULL CHECK(jsonb_typeof(proposal)='object'),
  authority_status text NOT NULL DEFAULT 'CUSTOMER_PROPOSED' CHECK(authority_status='CUSTOMER_PROPOSED'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,target_id,revision),
  FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id)
);
CREATE TABLE public.api_target_challenges (
  id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,
  nonce_hash char(64) NOT NULL,
  origin text NOT NULL,environment text NOT NULL,verification_version integer NOT NULL,
  target_revision integer NOT NULL,
  status text NOT NULL CHECK(status IN ('ISSUED','CONSUMED','REVOKED','EXPIRED')),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  UNIQUE(tenant_id,id),
  FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id)
);
CREATE UNIQUE INDEX api_target_one_issued_challenge ON public.api_target_challenges(tenant_id,target_id) WHERE status='ISSUED';
CREATE TABLE public.api_target_verification_evidence (
  id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,challenge_id uuid NOT NULL,
  evidence_type text NOT NULL CHECK(evidence_type IN ('SIGNED_SYNTHETIC_ATTESTATION','CUSTOMER_CLAIM')),
  evidence_sha256 char(64) NOT NULL,
  outcome text NOT NULL CHECK(outcome IN ('ACCEPTED_SYNTHETIC','REJECTED_UNVERIFIED')),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(tenant_id,id),UNIQUE(tenant_id,challenge_id,evidence_sha256),
  FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id),
  FOREIGN KEY(tenant_id,challenge_id) REFERENCES public.api_target_challenges(tenant_id,id)
);
CREATE TABLE public.api_target_verification_decisions (
  id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,challenge_id uuid NOT NULL,
  evidence_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('SYNTHETIC_VERIFIED_TEST_ONLY','PENDING_HOST_VERIFICATION')),
  decision_authority text NOT NULL CHECK(decision_authority IN ('SYNTHETIC_TEST_ONLY','NO_HOST_AUTHORITY')),
  origin text NOT NULL,environment text NOT NULL,verification_version integer NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(tenant_id,challenge_id),
  FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id),
  FOREIGN KEY(tenant_id,challenge_id) REFERENCES public.api_target_challenges(tenant_id,id),
  FOREIGN KEY(tenant_id,evidence_id) REFERENCES public.api_target_verification_evidence(tenant_id,id)
);
CREATE TABLE public.api_target_credentials (
  id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,
  reference text NOT NULL CHECK(length(reference) BETWEEN 12 AND 145),
  status text NOT NULL CHECK(status='UNVERIFIED_REFERENCE'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(tenant_id,target_id,reference),
  FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id)
);
CREATE TABLE public.api_target_events (
  id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,
  action text NOT NULL,revision integer NOT NULL,details jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id)
);
DO $rls$ DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY[
   'api_target_scopes','api_target_challenges','api_target_verification_evidence',
   'api_target_verification_decisions','api_target_credentials','api_target_events'
 ] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING (tenant_id = nullif(current_setting(''api.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',name);
  EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO api_family',name);
 END LOOP;
END $rls$;
CREATE INDEX api_targets_lookup ON public.api_targets(tenant_id,lifecycle,environment,created_at DESC);
CREATE INDEX api_challenges_lookup ON public.api_target_challenges(tenant_id,target_id,issued_at DESC);
CREATE INDEX api_target_events_lookup ON public.api_target_events(tenant_id,target_id,occurred_at DESC);

CREATE UNIQUE INDEX api_target_registration_idempotency ON public.api_targets(tenant_id,registration_key) WHERE registration_key IS NOT NULL;

-- Immutable customer/security review history: app and worker principals cannot rewrite accepted facts.
CREATE OR REPLACE FUNCTION public.api_phase1_immutable_audit() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'PHASE1_IMMUTABLE_HISTORY' USING ERRCODE='42501';
END $$;
CREATE TRIGGER no_scope_history_rewrite BEFORE UPDATE OR DELETE ON public.api_target_scopes
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER no_evidence_rewrite BEFORE UPDATE OR DELETE ON public.api_target_verification_evidence
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER no_decision_rewrite BEFORE UPDATE OR DELETE ON public.api_target_verification_decisions
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER no_target_event_rewrite BEFORE UPDATE OR DELETE ON public.api_target_events
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
