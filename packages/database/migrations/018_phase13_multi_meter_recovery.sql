-- Phase13 forward-only extension 018. Never rewrite existing 001-017 data.
-- These are test-only source-observation meters; never Main Platform permissions/billing.
DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['api_v13_entitlement_events','api_v13_reservations','api_v13_usage_ledger','api_v13_reconciliation'] LOOP
  EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I',t,t||'_feature_check');
  EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (feature IN (''IMMUTABLE_REPORT_OBSERVED'',''OFFLINE_API_ASSESSMENT_COMPLETED'',''GOVERNED_API_PT_COMPLETED''))',t,t||'_feature_check');
 END LOOP;
END $$;
-- Every old and new 017 accounting record is bound to version one; existing
-- rows acquire their additive default unchanged, not a new usage event.
DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['api_v13_entitlement_events','api_v13_reservations',
  'api_v13_usage_ledger','api_v13_reconciliation'] LOOP
  EXECUTE format('ALTER TABLE public.%I ADD COLUMN meter_version smallint NOT NULL DEFAULT 1 CHECK(meter_version=1)',t);
 END LOOP;
END $$;
-- Stores immutable independently validated source binding, not a customer-created counter.
CREATE TABLE public.api_v13_feature_sources (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,reservation_id uuid NOT NULL,
 feature text NOT NULL CHECK(feature IN ('OFFLINE_API_ASSESSMENT_COMPLETED','GOVERNED_API_PT_COMPLETED')),
 meter_version smallint NOT NULL DEFAULT 1 CHECK(meter_version=1),
 source_type text NOT NULL CHECK(source_type IN('PERSISTED_OFFLINE_REPORT','SIGNED_GOVERNED_SYNTHETIC_PT')),
 source_report_id uuid NOT NULL,source_assessment_id uuid NOT NULL,
 source_fingerprint char(64) NOT NULL CHECK(source_fingerprint ~ '^[a-f0-9]{64}$'),
 historical_permit_hash char(64) CHECK(historical_permit_hash ~ '^[a-f0-9]{64}$'),
 terminal_outcome text NOT NULL CHECK(terminal_outcome='COMPLETED'),
 entitlement_revision integer NOT NULL CHECK(entitlement_revision BETWEEN 1 AND 1000000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((feature='OFFLINE_API_ASSESSMENT_COMPLETED' AND source_type='PERSISTED_OFFLINE_REPORT' AND historical_permit_hash IS NULL)
    OR(feature='GOVERNED_API_PT_COMPLETED' AND source_type='SIGNED_GOVERNED_SYNTHETIC_PT' AND historical_permit_hash IS NOT NULL)),
 UNIQUE(tenant_id,reservation_id),UNIQUE(tenant_id,feature,source_report_id),
 FOREIGN KEY(tenant_id,reservation_id) REFERENCES public.api_v13_reservations(tenant_id,id),
 FOREIGN KEY(tenant_id,source_report_id) REFERENCES public.api_vapt11_reports(tenant_id,parent_assessment_id),
 FOREIGN KEY(tenant_id,source_assessment_id) REFERENCES public.api_assessments(tenant_id,id)
);
-- Deliberately separate test-only delivery projection; the real outbox remains immutable DISABLED.
CREATE UNIQUE INDEX api_v13_outbox_tenant_id ON public.api_v13_outbox(tenant_id,id);
CREATE TABLE public.api_v13_qa_delivery(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,outbox_id uuid NOT NULL,
 state text NOT NULL DEFAULT 'PENDING' CHECK(state IN('PENDING','LEASED','RETRY','ACKED','DEAD_LETTER')),
 attempt_count smallint NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 4),
 lease_token uuid,lease_until timestamptz,next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 acked_at timestamptz,diagnostic text CHECK(length(diagnostic)<=100),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((state='LEASED' AND lease_token IS NOT NULL AND lease_until IS NOT NULL AND acked_at IS NULL)
   OR(state='ACKED' AND lease_token IS NULL AND lease_until IS NULL AND acked_at IS NOT NULL)
   OR(state IN('PENDING','RETRY','DEAD_LETTER') AND lease_token IS NULL AND lease_until IS NULL AND acked_at IS NULL)),
 UNIQUE(tenant_id,outbox_id),UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,outbox_id) REFERENCES public.api_v13_outbox(tenant_id,id)
);
CREATE TABLE public.api_v13_qa_delivery_events(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,delivery_id uuid NOT NULL,
 code text NOT NULL CHECK(code IN('ENQUEUED','CLAIMED','RETRY_SCHEDULED','ACKED','STALE_REJECTED','DEAD_LETTER')),
 attempt_count integer NOT NULL CHECK(attempt_count BETWEEN 0 AND 4),
 diagnostic text CHECK(length(diagnostic)<=100),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,delivery_id) REFERENCES public.api_v13_qa_delivery(tenant_id,id)
);
CREATE TABLE public.api_v13_qa_sink_receipts(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,delivery_id uuid NOT NULL,
 redacted_payload_hash char(64) NOT NULL CHECK(redacted_payload_hash ~ '^[a-f0-9]{64}$'),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,delivery_id),
 FOREIGN KEY(tenant_id,delivery_id) REFERENCES public.api_v13_qa_delivery(tenant_id,id)
);
CREATE FUNCTION public.api_v13_qa_delivery_guard() RETURNS trigger LANGUAGE plpgsql
 SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.id,NEW.tenant_id,NEW.outbox_id,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.outbox_id,OLD.created_at)
 OR OLD.state IN('ACKED','DEAD_LETTER')
 OR NEW.attempt_count<OLD.attempt_count OR NEW.attempt_count>OLD.attempt_count+1
 OR (NEW.state='LEASED' AND (OLD.state NOT IN('PENDING','RETRY','LEASED') OR NEW.attempt_count<>OLD.attempt_count+1))
 OR (NEW.state='ACKED' AND OLD.state<>'LEASED')
 OR (NEW.state='RETRY' AND OLD.state<>'LEASED')
 OR (NEW.state='DEAD_LETTER' AND OLD.state<>'LEASED')
 THEN RAISE EXCEPTION 'PHASE13_QA_DELIVERY_INVALID_TRANSITION' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_qa_delivery BEFORE UPDATE ON public.api_v13_qa_delivery
 FOR EACH ROW EXECUTE FUNCTION public.api_v13_qa_delivery_guard();
DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['api_v13_feature_sources','api_v13_qa_delivery','api_v13_qa_delivery_events','api_v13_qa_sink_receipts'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING (tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,api_family,api_family_queue',t);
 END LOOP;
 FOREACH t IN ARRAY ARRAY['api_v13_feature_sources','api_v13_qa_delivery_events','api_v13_qa_sink_receipts'] LOOP
  EXECUTE format('CREATE TRIGGER immutable_%I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit()',t,t);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON public.api_v13_feature_sources TO api_family;
-- QA tables deliberately have no production app/worker grant; a CI-only DB role must
-- explicitly opt into the isolated state machine without touching production outbox.
GRANT SELECT,INSERT ON public.api_v13_qa_delivery,public.api_v13_qa_delivery_events,public.api_v13_qa_sink_receipts TO api_family;
GRANT UPDATE(state,attempt_count,lease_token,lease_until,next_attempt_at,acked_at,diagnostic) ON public.api_v13_qa_delivery TO api_family;
CREATE TRIGGER prevent_qa_delivery_delete BEFORE DELETE ON public.api_v13_qa_delivery
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
