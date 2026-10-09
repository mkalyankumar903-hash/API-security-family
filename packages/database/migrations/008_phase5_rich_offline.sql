-- Additive, tenant-bound, immutable phase05-v2 metadata only for new imports.
-- Never backfill/rewrite phase02-v1 inventory or historical evidence.
CREATE TABLE public.api_rich_inventories(
 specification_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 target_id uuid NOT NULL,
 normalization_version text NOT NULL DEFAULT 'phase05-v2' CHECK(normalization_version='phase05-v2'),
 raw_fingerprint char(64) NOT NULL,
 phase02_fingerprint char(64) NOT NULL,
 rich_fingerprint char(64) NOT NULL,
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,specification_id),
 FOREIGN KEY(tenant_id,specification_id) REFERENCES public.api_spec_inventories(tenant_id,specification_id),
 FOREIGN KEY(tenant_id,target_id) REFERENCES public.api_targets(tenant_id,id)
);
ALTER TABLE public.api_rich_inventories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_rich_inventories FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.api_rich_inventories
 USING(tenant_id=nullif(current_setting('api.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('api.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON public.api_rich_inventories TO api_family;
GRANT SELECT ON public.api_rich_inventories TO api_family_queue;
CREATE TRIGGER immutable_rich_inventory BEFORE UPDATE OR DELETE ON public.api_rich_inventories
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE INDEX api_rich_tenant_target ON public.api_rich_inventories(tenant_id,target_id,created_at DESC);
ALTER TABLE public.api_assessments DROP CONSTRAINT api_assessments_engine_version_check;
ALTER TABLE public.api_assessments ADD CONSTRAINT api_assessments_engine_version_check
 CHECK(engine_version IN ('legacy-v1','inventory-v1','auth-fixture-v1','inventory-v2'));
