-- Phase 04 is exclusively synthetic in-process fixture evaluation. Forward-only.
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_engine_version_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_engine_version_check
 CHECK (engine_version IN ('legacy-v1','inventory-v1','auth-fixture-v1'));
-- This engine uses the immutable Phase02 imported inventory provenance, not a Host network permit.
ALTER TABLE public.api_findings DROP CONSTRAINT api_findings_confidence_check;
ALTER TABLE public.api_findings ADD CONSTRAINT api_findings_confidence_check
 CHECK (confidence IN ('SPEC_OBSERVATION','SYNTHETIC_FIXTURE_OBSERVATION'));
ALTER TABLE public.api_findings DROP CONSTRAINT api_findings_validation_level_check;
ALTER TABLE public.api_findings ADD CONSTRAINT api_findings_validation_level_check
 CHECK (validation_level IN ('SPEC_ONLY','SYNTHETIC_AUTH_FIXTURE'));

CREATE TABLE public.api_auth_profiles(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,specification_id uuid NOT NULL,
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 fixture_version text NOT NULL CHECK(fixture_version IN ('secure-v1','broken-bola-v1')),
 scheme text NOT NULL CHECK(scheme IN ('BEARER','API_KEY','BASIC','OAUTH2','SESSION')),
 identity_key text NOT NULL CHECK(identity_key IN ('user-a','user-b','manager','admin')),
 role_name text NOT NULL CHECK(role_name IN ('reader','privileged','administrator')),
 credential_reference text NOT NULL CHECK(credential_reference ~ '^credref:[a-zA-Z0-9_-]{4,128}$'),
 environment text NOT NULL DEFAULT 'SYNTHETIC' CHECK(environment='SYNTHETIC'),
 status text NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED')),
 validation_status text NOT NULL DEFAULT 'PENDING' CHECK(validation_status IN ('PENDING','VALID','INVALID')),
 target_revision integer NOT NULL CHECK(target_revision>0),
 scope_revision integer NOT NULL CHECK(scope_revision>=0),
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id),
 FOREIGN KEY(tenant_id,specification_id) REFERENCES public.api_spec_inventories(tenant_id,specification_id)
);
CREATE TABLE public.api_auth_profile_events(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,profile_id uuid NOT NULL,revision integer NOT NULL,
 action text NOT NULL,summary jsonb NOT NULL CHECK(jsonb_typeof(summary)='object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,profile_id) REFERENCES public.api_auth_profiles(tenant_id,id)
);
CREATE TABLE public.api_auth_assessment_configs(
 assessment_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,profile_id uuid NOT NULL,
 profile_revision integer NOT NULL CHECK(profile_revision>0),
 fixture_version text NOT NULL CHECK(fixture_version IN ('secure-v1','broken-bola-v1')),
 fixture_policy_version text NOT NULL CHECK(fixture_policy_version='auth-policy-v1'),
 declared_schemes jsonb NOT NULL CHECK(jsonb_typeof(declared_schemes)='array'),
 target_revision integer NOT NULL CHECK(target_revision>0),
 scope_revision integer NOT NULL CHECK(scope_revision>=0),
 specification_version integer NOT NULL CHECK(specification_version>0),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_assessments(tenant_id,id),
 FOREIGN KEY(tenant_id,profile_id) REFERENCES public.api_auth_profiles(tenant_id,id)
);
CREATE TABLE public.api_auth_evaluations(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,assessment_id uuid NOT NULL,
 rule_id text NOT NULL,rule_revision text NOT NULL,
 fixture_version text NOT NULL,profile_id uuid NOT NULL,profile_revision integer NOT NULL,
 identity_key text NOT NULL,role_name text NOT NULL,operation_key text NOT NULL,
 expected text NOT NULL CHECK(expected IN ('ALLOW','DENY')),
 observed text NOT NULL CHECK(observed IN ('ALLOW','DENY','UNKNOWN')),
 http_status integer NOT NULL CHECK(http_status BETWEEN 100 AND 599),
 response_bytes integer NOT NULL CHECK(response_bytes BETWEEN 0 AND 65536),
 outcome text NOT NULL CHECK(outcome IN ('PASS','DEVIATION','UNKNOWN','SKIPPED')),
 fingerprint char(64) NOT NULL,fixture_only boolean NOT NULL CHECK(fixture_only),
 reason text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id,fingerprint),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_assessments(tenant_id,id),
 FOREIGN KEY(tenant_id,profile_id) REFERENCES public.api_auth_profiles(tenant_id,id)
);
DO $rls$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_auth_profiles','api_auth_profile_events','api_auth_assessment_configs','api_auth_evaluations']
 LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING (tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',tab);
 END LOOP;
END $rls$;
GRANT SELECT,INSERT,UPDATE ON public.api_auth_profiles TO api_family;
GRANT SELECT,INSERT ON public.api_auth_profile_events TO api_family;
GRANT SELECT,INSERT ON public.api_auth_assessment_configs TO api_family;
GRANT SELECT ON public.api_auth_evaluations TO api_family;
GRANT SELECT ON public.api_auth_profiles,public.api_auth_assessment_configs TO api_family_queue;
GRANT SELECT,INSERT ON public.api_auth_profile_events,public.api_auth_evaluations TO api_family_queue;
CREATE INDEX api_auth_profile_target ON public.api_auth_profiles(tenant_id,target_id,updated_at DESC);
CREATE INDEX api_auth_evaluation_assessment ON public.api_auth_evaluations(tenant_id,assessment_id,rule_id);
CREATE TRIGGER immutable_auth_profile_history BEFORE UPDATE OR DELETE ON public.api_auth_profile_events
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_auth_assessment_config BEFORE UPDATE OR DELETE ON public.api_auth_assessment_configs
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_auth_evaluation BEFORE UPDATE OR DELETE ON public.api_auth_evaluations
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
