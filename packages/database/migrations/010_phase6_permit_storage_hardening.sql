-- Phase06 additive migration; 009 and all preceding migrations stay unchanged.
-- Existing rows preserve non-secret claims and SHA-256 fingerprint. Worker
-- recomputes the HMAC with the ephemeral test signing key at each decision.
CREATE OR REPLACE FUNCTION public.api_pt_permit_content_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
 NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
 NEW.token_hash IS DISTINCT FROM OLD.token_hash OR NEW.claims IS DISTINCT FROM OLD.claims OR
 NEW.issued_at IS DISTINCT FROM OLD.issued_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
 NEW.consumed + NEW.reserved > (NEW.claims->>'maxEvaluations')::integer OR
 NEW.consumed < OLD.consumed OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at AND OLD.revoked_at IS NOT NULL
 THEN RAISE EXCEPTION 'PT_PERMIT_IMMUTABLE_OR_BUDGET' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
ALTER TABLE public.api_pt_permits DROP COLUMN signed_token;
