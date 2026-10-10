-- Phase13 additive, isolated commercial projection. Never alters Phase00-12 authorities.
CREATE TABLE public.api_v13_entitlement_events(
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, entitlement_id uuid NOT NULL,
 event_id uuid NOT NULL, revision integer NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 feature text NOT NULL CHECK(feature='IMMUTABLE_REPORT_OBSERVED'),
 limit_units integer NOT NULL CHECK(limit_units BETWEEN 0 AND 1000000),
 state text NOT NULL CHECK(state IN ('ISSUED','REVOKED')),
 issuer text NOT NULL CHECK(issuer='lumicsec-ci-synthetic-v13'),
 audience text NOT NULL CHECK(audience='api-family-v13-test'),
 payload_fingerprint char(64) NOT NULL CHECK(payload_fingerprint ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,event_id),UNIQUE(tenant_id,entitlement_id,revision));
CREATE INDEX api_v13_entitlement_latest ON public.api_v13_entitlement_events(tenant_id,feature,revision DESC,id);

CREATE TABLE public.api_v13_reservations(
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, entitlement_id uuid NOT NULL,
 feature text NOT NULL CHECK(feature='IMMUTABLE_REPORT_OBSERVED'),
 source_report_id uuid NOT NULL, month_start date NOT NULL,
 idempotency_key varchar(128) NOT NULL CHECK(idempotency_key ~ '^[a-zA-Z0-9:_-]{8,128}$'),
 units integer NOT NULL CHECK(units BETWEEN 1 AND 1000000),
 state text NOT NULL DEFAULT 'RESERVED' CHECK(state IN ('RESERVED','SETTLED','RELEASED','EXPIRED')),
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 settled_at timestamptz, UNIQUE(tenant_id,idempotency_key),
 UNIQUE(tenant_id,source_report_id,feature),
 FOREIGN KEY(tenant_id,source_report_id) REFERENCES public.api_vapt11_reports(tenant_id,parent_assessment_id));
CREATE INDEX api_v13_reservations_account ON public.api_v13_reservations(tenant_id,feature,month_start,state,expires_at);

CREATE TABLE public.api_v13_usage_ledger(
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, reservation_id uuid NOT NULL,
 feature text NOT NULL CHECK(feature='IMMUTABLE_REPORT_OBSERVED'),
 source_report_id uuid NOT NULL, month_start date NOT NULL,
 units integer NOT NULL CHECK(units BETWEEN 1 AND 1000000),
 source_fingerprint char(64) NOT NULL CHECK(source_fingerprint ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,reservation_id),UNIQUE(tenant_id,source_report_id,feature),
 FOREIGN KEY(tenant_id,source_report_id) REFERENCES public.api_vapt11_reports(tenant_id,parent_assessment_id),
 FOREIGN KEY(tenant_id,reservation_id) REFERENCES public.api_v13_reservations(tenant_id,id));
CREATE INDEX api_v13_usage_history ON public.api_v13_usage_ledger(tenant_id,feature,month_start,created_at DESC,id);

CREATE TABLE public.api_v13_event_inbox(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,event_id uuid NOT NULL,
 payload_fingerprint char(64) NOT NULL CHECK(payload_fingerprint ~ '^[a-f0-9]{64}$'),
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,event_id));
CREATE TABLE public.api_v13_outbox(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,source_usage_id uuid NOT NULL,
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND pg_column_size(payload)<=2048),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,source_usage_id),
 FOREIGN KEY(tenant_id,source_usage_id) REFERENCES public.api_v13_usage_ledger(tenant_id,id));
-- Reconciliation is an immutable local comparison; never a Host invoice/settlement.
CREATE TABLE public.api_v13_reconciliation(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,feature text NOT NULL CHECK(feature='IMMUTABLE_REPORT_OBSERVED'),
 month_start date NOT NULL, external_revision integer,
 local_units integer NOT NULL CHECK(local_units BETWEEN 0 AND 1000000000),
 external_units integer CHECK(external_units BETWEEN 0 AND 1000000000),
 external_fingerprint char(64) CHECK(external_fingerprint ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN('MATCHED','MISMATCH','PENDING_EXTERNAL_AUTHORITY','INVALID_SOURCE','UNSUPPORTED_CONTRACT')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,feature,month_start,external_revision,external_fingerprint));
CREATE INDEX api_v13_reconciliation_history ON public.api_v13_reconciliation(tenant_id,created_at DESC,id);
DO $security$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_v13_entitlement_events','api_v13_reservations','api_v13_usage_ledger',
 'api_v13_event_inbox','api_v13_outbox','api_v13_reconciliation'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING (tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['api_v13_entitlement_events','api_v13_usage_ledger','api_v13_event_inbox','api_v13_outbox','api_v13_reconciliation'] LOOP
  EXECUTE format('CREATE TRIGGER immutable_%I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit()',tab,tab);
 END LOOP;
END $security$;
CREATE FUNCTION public.api_v13_reservation_guard() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.id,NEW.tenant_id,NEW.entitlement_id,NEW.feature,NEW.source_report_id,NEW.month_start,NEW.idempotency_key,NEW.units,NEW.expires_at,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.entitlement_id,OLD.feature,OLD.source_report_id,OLD.month_start,OLD.idempotency_key,OLD.units,OLD.expires_at,OLD.created_at)
 OR OLD.state<>'RESERVED' OR NEW.state NOT IN('SETTLED','RELEASED','EXPIRED') OR
 (NEW.state='SETTLED' AND (NEW.settled_at IS NULL OR OLD.expires_at<=clock_timestamp())) OR
 (NEW.state<>'SETTLED' AND NEW.settled_at IS NOT NULL)
 THEN RAISE EXCEPTION 'PHASE13_RESERVATION_IMMUTABLE' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER api_v13_reservation_guard BEFORE UPDATE ON public.api_v13_reservations
 FOR EACH ROW EXECUTE FUNCTION public.api_v13_reservation_guard();
REVOKE ALL ON public.api_v13_entitlement_events,public.api_v13_reservations,public.api_v13_usage_ledger,
 public.api_v13_event_inbox,public.api_v13_outbox,public.api_v13_reconciliation
 FROM PUBLIC,api_family,api_family_queue;
GRANT SELECT,INSERT ON public.api_v13_entitlement_events,public.api_v13_reservations,
 public.api_v13_usage_ledger,public.api_v13_event_inbox,public.api_v13_outbox,
 public.api_v13_reconciliation TO api_family;
GRANT UPDATE(state,settled_at) ON public.api_v13_reservations TO api_family;
-- No queue role grants. No raw tokens, customer payment data or invoices.
