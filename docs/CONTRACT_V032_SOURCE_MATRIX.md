# v0.3.2 source and compatibility boundary

Authoritative local sources: v0.3.1 Candidate ZIP, Main Platform Review v0.3.2, Decision Register v0.3.2.
Final Contract Resolution / One-Shot Authorization: NOT LOCATED; final Host compatibility BLOCKED.
Decision: ACCEPTED IN PRINCIPLE WITH CHANGES / NOT FROZEN. C8 remains deferred.

Derived schemas (7) are provisional, non-frozen, and are NOT an independent authority to execute live traffic.
SCHEMA-01 (local derived provisional profile): READ_ONLY_PROBE and CONTROLLED_ACTIVE allow only GET/HEAD; OPTIONS is explicitly rejected until Main Platform authorizes it.
Upstream distinction: the untouched v0.3.1 candidate and v0.3.2 review discuss GET/HEAD/OPTIONS. This local stricter rule is NOT a modification to or freeze of the authoritative upstream contract.
SPEC_ONLY has exactly zero authorized network requests: maxRequests/max_requests=0, methods/allowed_methods=[], no permit request, no network ordinals. Queue jobs and offline spec operations remain enabled.
Wire-facing max_requests and request_ordinal are capped at 100000, including their upper boundary. Generic local safe-integer counters are distinct and grant no network authority.
SCHEMA-02 job-plan + permit-request: CONTROLLED_ACTIVE read-only; mutations only MUTATING_STAGING with Host approval, staging fixture and cleanup.
SCHEMA-03 permit-decision: denial cannot claim ALLOWED.
SCHEMA-04 permit-request ordinal now max 100000, with runtime ordinal<=authorized plan budget required.
No real Host-signed tokens, vector authority or permit service is implied.

Original v0.3.1 exact SHA-256 digests:

- approved-operation.schema.json original_sha256=2072dc605cb210341b2875d79d6420b84145bee8d7c68f845a9f3a987f945ae4
- host-delegated-invocation.schema.json original_sha256=a278e50b5724d8e904782b5ce19cb4031709e13fdf7683166e9718eef1dea7a2
- job-plan.schema.json original_sha256=0f5d312280b7ab57ae533c529c1d7f7e5d1168ac9cfe09bf936dc0c3f6b5a8d6
- permit-binding-fields.schema.json original_sha256=4995e90747a53c856f867131ad637791ae30bade73d5423b5773c72af7fd7dc8
- permit-decision.schema.json original_sha256=8dfaa821b83f1824c899932334d906d328c79e16b0a0d909ec8b22e7396b0b69
- permit-request.schema.json original_sha256=0c5b69509a91223e24736cfe62e140f040a6aa30ffd3d88c208b4db92c29b6f3
- trusted-lease-proof.schema.json original_sha256=55eb84655a2b56556b03c863b469dc917fa1a0c6421b1d61fd951dbe4cbbbd72
ZIP sha256: eeb2b41c786f247545a270fb0b110d2eb43a0944028e913541acc77201b74ea5
