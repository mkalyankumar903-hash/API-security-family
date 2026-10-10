-- Phase13 forward-only QA privilege repair: do not rewrite migrations 001-018.
REVOKE ALL ON TABLE public.api_v13_qa_delivery,public.api_v13_qa_delivery_events,
 public.api_v13_qa_sink_receipts FROM PUBLIC,api_family,api_family_queue;
DO $qa$
BEGIN
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='api_family_qa_ci') THEN
  -- Optional CI-only SQL role: production without role receives no grants.
  GRANT USAGE ON SCHEMA public TO api_family_qa_ci;
  GRANT SELECT ON public.api_v13_outbox TO api_family_qa_ci;
  GRANT SELECT,INSERT ON public.api_v13_qa_delivery,
   public.api_v13_qa_delivery_events,public.api_v13_qa_sink_receipts TO api_family_qa_ci;
  GRANT UPDATE(state,attempt_count,lease_token,lease_until,next_attempt_at,acked_at,diagnostic)
   ON public.api_v13_qa_delivery TO api_family_qa_ci;
 END IF;
END $qa$;
-- Existing FORCE RLS, immutable triggers and DISABLED real outbox are untouched.
