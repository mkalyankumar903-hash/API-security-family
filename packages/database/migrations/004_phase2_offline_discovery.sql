-- Phase 02 forward-only, tenant-isolated inventory on the existing Phase 0 api_specifications authority.
-- Never mutate historical api_specifications / api_operations / reports / findings.
CREATE TABLE public.api_spec_imports (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL,target_id uuid NOT NULL,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),
 fingerprint char(64) NOT NULL, status text NOT NULL
 CHECK(status IN ('RECEIVED','VALIDATING','NORMALIZING','COMPLETED','FAILED')),
 specification_id uuid, error_code text,
 received_at timestamptz NOT NULL DEFAULT now(),completed_at timestamptz,
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,target_id,idempotency_key),
 FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id),
 FOREIGN KEY(tenant_id,specification_id) REFERENCES public.api_specifications(tenant_id,id)
);
CREATE TABLE public.api_spec_inventories(
 specification_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,
 version_number integer NOT NULL CHECK(version_number>=1),
 original_format text NOT NULL CHECK(original_format IN ('OPENAPI_3_0','OPENAPI_3_1','SWAGGER_2','POSTMAN_2_1')),
 raw_fingerprint char(64) NOT NULL, normalized_fingerprint char(64) NOT NULL,
 normalization_version text NOT NULL CHECK(normalization_version='phase02-v1'),
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object'),
 assessment_source text,coverage text NOT NULL CHECK(coverage IN ('SUPPORTED_PROFILE','PARTIAL')),
 selected boolean NOT NULL DEFAULT false, imported_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,specification_id),UNIQUE(tenant_id,target_id,version_number),
 UNIQUE(tenant_id,target_id,raw_fingerprint),
 FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id),
 FOREIGN KEY(tenant_id,specification_id) REFERENCES public.api_specifications(tenant_id,id)
);
CREATE UNIQUE INDEX api_spec_one_selected_version ON public.api_spec_inventories(tenant_id,target_id) WHERE selected;
CREATE TABLE public.api_inventory_operations(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,specification_id uuid NOT NULL,
 operation_key text NOT NULL, method text NOT NULL,path text NOT NULL,
 auth_state text NOT NULL, tags text[] NOT NULL DEFAULT '{}',
 pointer text NOT NULL, projection jsonb NOT NULL,
 UNIQUE(tenant_id,specification_id,operation_key),
 FOREIGN KEY(tenant_id,specification_id) REFERENCES public.api_spec_inventories(tenant_id,specification_id)
);
CREATE TABLE public.api_spec_diffs(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,target_id uuid NOT NULL,
 from_specification uuid NOT NULL,to_specification uuid NOT NULL,
 projection jsonb NOT NULL,calculated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,from_specification,to_specification),
 FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id),
 FOREIGN KEY(tenant_id,from_specification) REFERENCES public.api_spec_inventories(tenant_id,specification_id),
 FOREIGN KEY(tenant_id,to_specification) REFERENCES public.api_spec_inventories(tenant_id,specification_id)
);
CREATE TABLE public.api_spec_import_events(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,import_id uuid NOT NULL,
 state text NOT NULL,code text,occurred_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,import_id) REFERENCES public.api_spec_imports(tenant_id,id)
);
DO $phase2$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_spec_imports','api_spec_inventories','api_inventory_operations','api_spec_diffs','api_spec_import_events']
 LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING (tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',tab);
  EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO api_family',tab);
 END LOOP;
END $phase2$;
-- Immutable versioned snapshots, normalized operations, diffs, and historical import event transitions.
DO $immutable$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_inventory_operations','api_spec_diffs','api_spec_import_events']
 LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit()','immutable_'||tab,tab);
 END LOOP;
END $immutable$;
CREATE OR REPLACE FUNCTION public.api_phase2_restrict_inventory_changes() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.specification_id IS DISTINCT FROM OLD.specification_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
 OR NEW.target_id IS DISTINCT FROM OLD.target_id OR NEW.version_number IS DISTINCT FROM OLD.version_number
 OR NEW.raw_fingerprint IS DISTINCT FROM OLD.raw_fingerprint OR NEW.normalized_fingerprint IS DISTINCT FROM OLD.normalized_fingerprint
 OR NEW.snapshot IS DISTINCT FROM OLD.snapshot OR NEW.assessment_source IS DISTINCT FROM OLD.assessment_source
 OR NEW.original_format IS DISTINCT FROM OLD.original_format
 THEN RAISE EXCEPTION 'IMMUTABLE_INVENTORY_CONTENT' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_inventory_content BEFORE UPDATE ON public.api_spec_inventories
 FOR EACH ROW EXECUTE FUNCTION public.api_phase2_restrict_inventory_changes();
CREATE TRIGGER no_inventory_deletion BEFORE DELETE ON public.api_spec_inventories
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE INDEX api_spec_inventory_target_versions ON public.api_spec_inventories(tenant_id,target_id,version_number DESC);
CREATE INDEX api_inventory_operation_search ON public.api_inventory_operations(tenant_id,specification_id,method,path);
CREATE INDEX api_spec_import_target ON public.api_spec_imports(tenant_id,target_id,received_at DESC);
