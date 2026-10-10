-- Phase 11: additive, isolated, synthetic-only parent/child VAPT projection.
-- Previous migrations, permit authority, private queue and canonical findings remain untouched.
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_engine_version_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_engine_version_check
 CHECK(engine_version IN('legacy-v1','inventory-v1','inventory-v2','auth-fixture-v1',
  'pt-fixture-v1','pt-detection-v1','pt-orchestrator-v1','autonomous-api-vapt-v1'));
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_mode_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_mode_check
 CHECK((mode='SPEC_ONLY' AND engine_version NOT IN('pt-fixture-v1','pt-detection-v1','pt-orchestrator-v1'))
  OR (mode='SYNTHETIC_PT_FIXTURE' AND engine_version IN
   ('pt-fixture-v1','pt-detection-v1','pt-orchestrator-v1','autonomous-api-vapt-v1')));
-- This same-target, same-specification FK is stronger than merely tenant-bound IDs.
CREATE UNIQUE INDEX api_vapt11_child_context ON public.api_assessments
 (tenant_id,target_id,specification_id,id);
CREATE TABLE public.api_vapt11_assessments(
 parent_assessment_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,
 specification_id uuid NOT NULL,offline_assessment_id uuid NOT NULL,
 pt_assessment_id uuid,mode text NOT NULL CHECK(mode IN('OFFLINE_ONLY','GOVERNED_SYNTHETIC')),
 plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object' AND
  plan->>'schemaVersion'='autonomous-api-vapt-plan-v1' AND
  plan->>'syntheticOnly'='true' AND plan->>'customerNetworkRequests'='0'),
 fingerprint char(64) NOT NULL CHECK(fingerprint ~ '^[a-f0-9]{64}$'),
 lineage_parent_id uuid,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,parent_assessment_id),
 UNIQUE(tenant_id,offline_assessment_id),
 UNIQUE(tenant_id,pt_assessment_id),
 FOREIGN KEY(tenant_id,target_id,specification_id,parent_assessment_id)
  REFERENCES public.api_assessments(tenant_id,target_id,specification_id,id),
 FOREIGN KEY(tenant_id,target_id,specification_id,offline_assessment_id)
  REFERENCES public.api_assessments(tenant_id,target_id,specification_id,id),
 FOREIGN KEY(tenant_id,target_id,specification_id,pt_assessment_id)
  REFERENCES public.api_assessments(tenant_id,target_id,specification_id,id),
 FOREIGN KEY(tenant_id,pt_assessment_id)
  REFERENCES public.api_pt9_plans(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,lineage_parent_id)
  REFERENCES public.api_vapt11_assessments(tenant_id,parent_assessment_id),
 CHECK((mode='OFFLINE_ONLY' AND pt_assessment_id IS NULL) OR
       (mode='GOVERNED_SYNTHETIC' AND pt_assessment_id IS NOT NULL)),
 CHECK(parent_assessment_id<>offline_assessment_id AND
       (pt_assessment_id IS NULL OR (pt_assessment_id<>parent_assessment_id
       AND pt_assessment_id<>offline_assessment_id))),
 CHECK(lineage_parent_id IS NULL OR lineage_parent_id<>parent_assessment_id)
);
CREATE TABLE public.api_vapt11_correlations(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,parent_assessment_id uuid NOT NULL,
 stable_key char(64) NOT NULL CHECK(stable_key ~ '^[a-f0-9]{64}$'),
 source text NOT NULL CHECK(source IN('SPEC_ONLY','SYNTHETIC_PT','RELATED_EVIDENCE')),
 projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object' AND
  projection->>'verifiedFixed' IS DISTINCT FROM 'true'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,parent_assessment_id,stable_key),
 FOREIGN KEY(tenant_id,parent_assessment_id)
  REFERENCES public.api_vapt11_assessments(tenant_id,parent_assessment_id)
);
CREATE TABLE public.api_vapt11_reports(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,parent_assessment_id uuid NOT NULL,
 projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object' AND
  projection->>'schemaVersion'='autonomous-api-vapt-report-v1' AND
  projection->>'syntheticOnly'='true' AND
  projection->>'verifiedFixed'='false' AND
  projection->>'customerRuntimeVerified'='false' AND
  projection->>'status'='COMPLETED'),
 fingerprint char(64) NOT NULL CHECK(fingerprint ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,parent_assessment_id),
 FOREIGN KEY(tenant_id,parent_assessment_id)
  REFERENCES public.api_vapt11_assessments(tenant_id,parent_assessment_id)
);
CREATE TABLE public.api_vapt11_terminal(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,parent_assessment_id uuid NOT NULL,
 status text NOT NULL CHECK(status IN('FAILED','CANCELLED')),code text NOT NULL,
 projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object' AND
  projection->>'status' IN('FAILED','CANCELLED')),
 fingerprint char(64) NOT NULL CHECK(fingerprint ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,parent_assessment_id),
 FOREIGN KEY(tenant_id,parent_assessment_id)
  REFERENCES public.api_vapt11_assessments(tenant_id,parent_assessment_id)
);
CREATE TABLE public.api_vapt11_events(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,parent_assessment_id uuid NOT NULL,
 code text NOT NULL CHECK(length(code) BETWEEN 1 AND 100),
 details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(details)='object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,parent_assessment_id)
  REFERENCES public.api_vapt11_assessments(tenant_id,parent_assessment_id)
);
DO $rls$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_vapt11_assessments','api_vapt11_correlations','api_vapt11_reports',
  'api_vapt11_terminal','api_vapt11_events'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING(
   tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)
   WITH CHECK(tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',tab);
  EXECUTE format('CREATE TRIGGER immutable_%I BEFORE UPDATE OR DELETE ON public.%I
   FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit()',tab,tab);
 END LOOP;
END $rls$;
GRANT SELECT ON public.api_vapt11_assessments,public.api_vapt11_correlations,
 public.api_vapt11_reports,public.api_vapt11_terminal,public.api_vapt11_events
 TO api_family,api_family_queue;
GRANT INSERT ON public.api_vapt11_assessments,public.api_vapt11_events TO api_family;
GRANT INSERT ON public.api_vapt11_correlations,public.api_vapt11_reports,
 public.api_vapt11_terminal,public.api_vapt11_events TO api_family_queue;
GRANT INSERT ON public.api_vapt11_terminal TO api_family;
CREATE INDEX api_vapt11_history ON public.api_vapt11_assessments(tenant_id,target_id,created_at DESC,parent_assessment_id);
CREATE INDEX api_vapt11_lineage ON public.api_vapt11_assessments(tenant_id,lineage_parent_id);
CREATE INDEX api_vapt11_correlated ON public.api_vapt11_correlations(tenant_id,parent_assessment_id,source,stable_key);
-- Context validation is done at admission using transactionally locked authoritative
-- assessments. The composite FKs forbid wrong tenant/target/spec child identities.
