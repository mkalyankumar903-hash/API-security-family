-- SECURITY BOUNDARY: admin-only one-time migration. Service and worker use different DB principals.
CREATE SCHEMA IF NOT EXISTS api_queue AUTHORIZATION api_family_queue;
ALTER TABLE public.api_assessment_queue SET SCHEMA api_queue;
ALTER TABLE api_queue.api_assessment_queue OWNER TO api_family_queue;
REVOKE ALL ON SCHEMA api_queue FROM PUBLIC, api_family;
REVOKE ALL ON api_queue.api_assessment_queue FROM PUBLIC, api_family;
GRANT USAGE ON SCHEMA public TO api_family_queue;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO api_family_queue;

CREATE OR REPLACE FUNCTION public.api_enqueue_assessment(p_job uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, api_queue AS $$
DECLARE t uuid := nullif(current_setting('api.tenant_id',true),'')::uuid;
BEGIN
  IF t IS NULL THEN RAISE EXCEPTION 'NO_TENANT_CONTEXT' USING ERRCODE='42501'; END IF;
  INSERT INTO api_queue.api_assessment_queue(assessment_id,tenant_id)
    SELECT id,tenant_id FROM public.api_assessments
    WHERE id=p_job AND tenant_id=t AND status='QUEUED'
    ON CONFLICT (assessment_id) DO NOTHING;
END $$;
ALTER FUNCTION public.api_enqueue_assessment(uuid) OWNER TO api_family_queue;
REVOKE ALL ON FUNCTION public.api_enqueue_assessment(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.api_enqueue_assessment(uuid) TO api_family;

CREATE OR REPLACE FUNCTION public.api_cancel_assessment(p_job uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, api_queue AS $$
DECLARE t uuid := nullif(current_setting('api.tenant_id',true),'')::uuid;
DECLARE did_cancel boolean := false;
BEGIN
  IF t IS NULL THEN RAISE EXCEPTION 'NO_TENANT_CONTEXT' USING ERRCODE='42501'; END IF;
  -- Align with worker lock order: queue row first, assessment state second.
  PERFORM 1 FROM api_queue.api_assessment_queue
    WHERE assessment_id=p_job AND tenant_id=t FOR UPDATE;
  UPDATE public.api_assessments
    SET status='CANCELLED',completed_at=now()
    WHERE id=p_job AND tenant_id=t AND status IN ('QUEUED','PROCESSING');
  did_cancel := FOUND;
  IF did_cancel THEN
    DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=p_job AND tenant_id=t;
  END IF;
  RETURN did_cancel;
END $$;
ALTER FUNCTION public.api_cancel_assessment(uuid) OWNER TO api_family_queue;
REVOKE ALL ON FUNCTION public.api_cancel_assessment(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.api_cancel_assessment(uuid) TO api_family;
