-- Phase 12: isolated presentation/customer workflow metadata.
-- Canonical Phase 11 findings/reports and all execution authorities remain immutable.
CREATE TABLE public.api_v12_annotations (
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 parent_assessment_id uuid NOT NULL,
 stable_key char(64) NOT NULL CHECK(stable_key ~ '^[a-f0-9]{64}$'),
 version integer NOT NULL CHECK(version BETWEEN 1 AND 1000000),
 state text NOT NULL CHECK(state IN(
  'NEEDS_REVIEW','INVESTIGATING','REMEDIATION_PLANNED','FIX_CLAIMED','DEFERRED','ACCEPTED_FOR_REVIEW')),
 note text NOT NULL DEFAULT '' CHECK(length(note)<=1000),
 actor_context text NOT NULL DEFAULT 'ISOLATED_TENANT_CONTEXT' CHECK(actor_context='ISOLATED_TENANT_CONTEXT'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,parent_assessment_id,stable_key,version),
 FOREIGN KEY(tenant_id,parent_assessment_id,stable_key)
  REFERENCES public.api_vapt11_correlations(tenant_id,parent_assessment_id,stable_key)
);
CREATE TABLE public.api_v12_branding (
 tenant_id uuid PRIMARY KEY,
 display_name text NOT NULL CHECK(length(display_name) BETWEEN 1 AND 100),
 report_title text NOT NULL CHECK(length(report_title) BETWEEN 1 AND 120),
 accent_hex text NOT NULL CHECK(accent_hex ~ '^#[0-9A-Fa-f]{6}$'),
 version integer NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 1000000),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.api_v12_shares (
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 parent_assessment_id uuid NOT NULL,
 idempotency_key varchar(128) NOT NULL CHECK(idempotency_key ~ '^[a-zA-Z0-9:_-]{8,128}$'),
 duration_seconds integer NOT NULL CHECK(duration_seconds BETWEEN 300 AND 86400),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 revoked_at timestamptz,
 UNIQUE(tenant_id,idempotency_key),
 FOREIGN KEY(tenant_id,parent_assessment_id)
  REFERENCES public.api_vapt11_reports(tenant_id,parent_assessment_id)
);
CREATE TABLE public.api_v12_report_audit (
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 parent_assessment_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN (
  'PRESENTATION_VIEWED','JSON_EXPORTED','PDF_EXPORTED','BRANDING_UPDATED',
  'SHARE_CREATED','SHARE_VIEWED','SHARE_REVOKED','ANNOTATION_ADDED')),
 subject_id uuid,
 metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(metadata)='object' AND pg_column_size(metadata)<=1024),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,parent_assessment_id)
  REFERENCES public.api_vapt11_reports(tenant_id,parent_assessment_id)
);
DO $security$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_v12_annotations','api_v12_branding','api_v12_shares','api_v12_report_audit'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING(
   tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)
   WITH CHECK(tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['api_v12_annotations','api_v12_report_audit'] LOOP
  EXECUTE format('CREATE TRIGGER immutable_%I BEFORE UPDATE OR DELETE ON public.%I
   FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit()',tab,tab);
 END LOOP;
END $security$;
CREATE FUNCTION public.api_v12_branding_guard() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.version<>OLD.version+1 OR
    NEW.updated_at<OLD.updated_at THEN
  RAISE EXCEPTION 'PHASE12_BRANDING_VERSION_CONFLICT' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER api_v12_branding_guard BEFORE UPDATE ON public.api_v12_branding
 FOR EACH ROW EXECUTE FUNCTION public.api_v12_branding_guard();
CREATE FUNCTION public.api_v12_share_revoke_guard() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.id,NEW.tenant_id,NEW.parent_assessment_id,NEW.idempotency_key,
        NEW.duration_seconds,NEW.created_at,NEW.expires_at)
    IS DISTINCT FROM
    ROW(OLD.id,OLD.tenant_id,OLD.parent_assessment_id,OLD.idempotency_key,
        OLD.duration_seconds,OLD.created_at,OLD.expires_at)
    OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
  RAISE EXCEPTION 'PHASE12_SHARE_IMMUTABLE_OR_REVOKED' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER api_v12_share_revoke_guard BEFORE UPDATE ON public.api_v12_shares
 FOR EACH ROW EXECUTE FUNCTION public.api_v12_share_revoke_guard();
REVOKE ALL ON public.api_v12_annotations,public.api_v12_branding,public.api_v12_shares,
 public.api_v12_report_audit FROM PUBLIC,api_family,api_family_queue;
GRANT SELECT,INSERT ON public.api_v12_annotations TO api_family;
GRANT SELECT,INSERT ON public.api_v12_branding TO api_family;
GRANT UPDATE(display_name,report_title,accent_hex,version,updated_at) ON public.api_v12_branding TO api_family;
GRANT SELECT,INSERT ON public.api_v12_shares TO api_family;
GRANT UPDATE(revoked_at) ON public.api_v12_shares TO api_family;
GRANT SELECT,INSERT ON public.api_v12_report_audit TO api_family;
CREATE INDEX api_v12_annotation_recent ON public.api_v12_annotations
 (tenant_id,parent_assessment_id,stable_key,version DESC);
CREATE INDEX api_v12_report_audit_recent ON public.api_v12_report_audit
 (tenant_id,parent_assessment_id,created_at DESC,id);
CREATE INDEX api_v12_shares_expiry ON public.api_v12_shares
 (tenant_id,parent_assessment_id,expires_at) WHERE revoked_at IS NULL;
-- Retention: all audit/history is preserved; future Host data retention authority required.
