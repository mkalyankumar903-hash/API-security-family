-- Phase 10 additive worker-safety metadata; older migrations and governor ledger remain authoritative.
-- Private queue remains owned by the isolated worker principal.
ALTER TABLE api_queue.api_assessment_queue
 ADD COLUMN claim_generation bigint NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
 ADD COLUMN claimed_at timestamptz,
 ADD COLUMN last_heartbeat_at timestamptz,
 ADD COLUMN next_eligible_at timestamptz,
 ADD COLUMN retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count BETWEEN 0 AND 4),
 ADD COLUMN last_error_code text CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 96),
 ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX api_worker_eligibility_v1 ON api_queue.api_assessment_queue
 (next_eligible_at, locked_until, created_at, assessment_id);
CREATE INDEX api_worker_active_tenant_v1 ON api_queue.api_assessment_queue(tenant_id,locked_until);

-- The single lock gate serializes tenant-capacity admissions. Competing pollers
-- skip the busy gate instead of waiting indefinitely, while row claims remain SKIP LOCKED.
CREATE TABLE api_queue.api_worker_claim_gate(id boolean PRIMARY KEY CHECK(id));
INSERT INTO api_queue.api_worker_claim_gate(id) VALUES(true);
ALTER TABLE api_queue.api_worker_claim_gate OWNER TO api_family_queue;

-- Fair selection is based on the last *successful* claim, never user-supplied priority.
CREATE TABLE api_queue.api_worker_tenant_schedule(
 tenant_id uuid PRIMARY KEY, last_claimed_at timestamptz NOT NULL
);
ALTER TABLE api_queue.api_worker_tenant_schedule OWNER TO api_family_queue;

CREATE TABLE public.api_worker_attempts(
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, assessment_id uuid NOT NULL,
 claim_generation bigint NOT NULL CHECK(claim_generation>0),
 claim_token uuid NOT NULL,
 state text NOT NULL CHECK(state IN('ACTIVE','COMPLETED','FAILED','LOST','CANCELLED')),
 started_at timestamptz NOT NULL DEFAULT now(),
 last_heartbeat_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz,
 failure_code text CHECK(failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 96),
 UNIQUE(tenant_id,assessment_id,claim_generation),
 UNIQUE(claim_token),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_assessments(tenant_id,id)
);
CREATE INDEX api_worker_attempts_history_v1 ON public.api_worker_attempts(tenant_id,assessment_id,started_at DESC);
CREATE TABLE public.api_worker_events(
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, assessment_id uuid NOT NULL,
 attempt_id uuid, kind text NOT NULL CHECK(kind IN
 ('CLAIMED','HEARTBEAT','TAKEOVER','RETRY_SCHEDULED','RETRY_EXHAUSTED','QUARANTINED','CANCELLED','FAILED','COMPLETED','LEASE_LOST')),
 code text NOT NULL CHECK(length(code) BETWEEN 1 AND 96),
 occurred_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_assessments(tenant_id,id),
 FOREIGN KEY(attempt_id) REFERENCES public.api_worker_attempts(id)
);
CREATE INDEX api_worker_events_history_v1 ON public.api_worker_events(tenant_id,assessment_id,occurred_at DESC);
CREATE TABLE public.api_worker_quarantine(
 assessment_id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
 reason_code text NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 96),
 attempts integer NOT NULL CHECK(attempts BETWEEN 0 AND 5),
 quarantined_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,assessment_id),
 FOREIGN KEY(tenant_id,assessment_id) REFERENCES public.api_assessments(tenant_id,id)
);
DO $rls$ DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['api_worker_attempts','api_worker_events','api_worker_quarantine'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING (tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''api.tenant_id'',true),'''')::uuid)',tab);
 END LOOP;
END $rls$;
GRANT SELECT ON public.api_worker_attempts,public.api_worker_events,public.api_worker_quarantine TO api_family,api_family_queue;
GRANT INSERT,UPDATE(state,last_heartbeat_at,finished_at,failure_code) ON public.api_worker_attempts TO api_family_queue;
GRANT INSERT ON public.api_worker_events,public.api_worker_quarantine TO api_family_queue;
-- Audit records and terminal quarantine are append-only for every application/worker role.
CREATE TRIGGER immutable_worker_event BEFORE UPDATE OR DELETE ON public.api_worker_events
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();
CREATE TRIGGER immutable_worker_quarantine BEFORE UPDATE OR DELETE ON public.api_worker_quarantine
 FOR EACH ROW EXECUTE FUNCTION public.api_phase1_immutable_audit();

-- Minimal SECURITY DEFINER read-only projection: no customer-facing queue privileges.
CREATE FUNCTION public.api_worker_safe_queue_status(p_assessment uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,api_queue AS $$
 SELECT jsonb_build_object(
  'queueState',CASE
   WHEN q.claim_token IS NOT NULL AND q.locked_until>clock_timestamp() THEN 'LEASED'
   WHEN q.next_eligible_at>clock_timestamp() THEN 'RETRY_DELAYED'
   WHEN q.claim_token IS NOT NULL AND q.locked_until<=clock_timestamp() THEN 'EXPIRED'
   ELSE 'QUEUED' END,
  'claimGeneration',q.claim_generation,
  'lockedUntil',q.locked_until,
  'lastHeartbeatAt',q.last_heartbeat_at,
  'nextEligibleAt',q.next_eligible_at,
  'retryCount',q.retry_count,
  'lastErrorCode',q.last_error_code,
  'queuedAt',q.created_at)
 FROM api_queue.api_assessment_queue q
 WHERE q.assessment_id=p_assessment
 AND q.tenant_id=nullif(current_setting('api.tenant_id',true),'')::uuid
 AND EXISTS(SELECT 1 FROM public.api_assessments a
  WHERE a.id=q.assessment_id AND a.tenant_id=q.tenant_id)
$$;
ALTER FUNCTION public.api_worker_safe_queue_status(uuid) OWNER TO api_family_queue;
REVOKE ALL ON FUNCTION public.api_worker_safe_queue_status(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.api_worker_safe_queue_status(uuid) TO api_family;

-- Preserve the historical tenant-validated SECURITY DEFINER enqueue API while
-- bounding queue depth. The per-tenant transaction advisory gate makes the
-- count+insert atomic under parallel customer submissions.
CREATE OR REPLACE FUNCTION public.api_enqueue_assessment(p_job uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,api_queue AS $$
DECLARE t uuid := nullif(current_setting('api.tenant_id',true),'')::uuid;
DECLARE queued integer;
BEGIN
 IF t IS NULL THEN RAISE EXCEPTION 'NO_TENANT_CONTEXT' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(t::text,424242));
 -- Existing idempotent queued jobs are never denied or reinserted.
 IF EXISTS(SELECT 1 FROM api_queue.api_assessment_queue q WHERE q.assessment_id=p_job AND q.tenant_id=t) THEN RETURN; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.api_assessments a WHERE a.id=p_job AND a.tenant_id=t AND a.status='QUEUED') THEN RETURN; END IF;
 SELECT count(*)::int INTO queued FROM api_queue.api_assessment_queue WHERE tenant_id=t;
 IF queued>=64 THEN
   RAISE EXCEPTION 'QUEUE_TENANT_CAPACITY_EXCEEDED' USING ERRCODE='PT001';
 END IF;
 INSERT INTO api_queue.api_assessment_queue(assessment_id,tenant_id)
  SELECT id,tenant_id FROM public.api_assessments
  WHERE id=p_job AND tenant_id=t AND status='QUEUED'
  ON CONFLICT(assessment_id) DO NOTHING;
END $$;
ALTER FUNCTION public.api_enqueue_assessment(uuid) OWNER TO api_family_queue;
REVOKE ALL ON FUNCTION public.api_enqueue_assessment(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.api_enqueue_assessment(uuid) TO api_family;
