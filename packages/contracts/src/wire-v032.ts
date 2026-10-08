/**
 * Provisional wire semantics from the v0.3.1 candidate + v0.3.2 formal review.
 * Never used as an independent Host permit authority. Runtime remains SPEC_ONLY.
 */
export type WirePlan = {
  execution_mode:string;
  environment_class:string;
  allowed_methods:string[];
  allowed_origins:string[];
  allowed_paths:string[];
  approved_operations: {method:string; origin:string; path_template:string; body_schema_digest:string|null; credential_profile_reference?:string|null}[];
  max_requests:number;
  plan_digest:string;
  scope_hash:string;
  credential_profile_reference:string|null;
  mutation_approval_reference:string|null;
  fixture_set_reference:string|null;
  cleanup_verification_required:boolean;
};
export type WirePermitRequest = {
  execution_mode:string; method:string; request_ordinal:number; plan_digest:string;
  scope_hash:string; canonical_request_url:string; normalized_path:string;
  credential_profile_reference:string|null; mutation_approval_reference:string|null;
  request_body_digest:string|null;
};
export function verifyWirePlanPermit(plan:WirePlan,permit:WirePermitRequest):void {
  if (!Number.isSafeInteger(plan.max_requests) || plan.max_requests < 0 || plan.max_requests > 100000 ||
      !Number.isSafeInteger(permit.request_ordinal) || permit.request_ordinal < 1 ||
      permit.request_ordinal > plan.max_requests) throw new Error("WIRE_BUDGET_MISMATCH");
  if (plan.execution_mode!==permit.execution_mode || plan.plan_digest!==permit.plan_digest ||
      plan.scope_hash!==permit.scope_hash) throw new Error("WIRE_PLAN_BINDING_MISMATCH");
  if (!plan.allowed_methods.includes(permit.method)) throw new Error("WIRE_METHOD_NOT_APPROVED");
  if (plan.credential_profile_reference!==permit.credential_profile_reference) throw new Error("WIRE_CREDENTIAL_MISMATCH");
  let url:URL;
  try{url=new URL(permit.canonical_request_url);}catch{throw new Error("WIRE_URL_INVALID");}
  if(url.protocol!=="https:" || url.username || url.password || url.hash || url.search ||
      !plan.allowed_origins.includes(url.origin) || !plan.allowed_paths.includes(permit.normalized_path) ||
      url.pathname!==permit.normalized_path) throw new Error("WIRE_SCOPE_MISMATCH");
  const mutation=["POST","PUT","PATCH","DELETE"].includes(permit.method);
  if(plan.execution_mode==="READ_ONLY_PROBE" || plan.execution_mode==="CONTROLLED_ACTIVE"){
    if(mutation || permit.mutation_approval_reference!==null) throw new Error("WIRE_READ_ONLY_POLICY");
  }
  if(mutation) {
    if(plan.execution_mode!=="MUTATING_STAGING" || plan.environment_class!=="staging" ||
      !plan.mutation_approval_reference || !plan.fixture_set_reference || !plan.cleanup_verification_required ||
      permit.mutation_approval_reference!==plan.mutation_approval_reference ||
      !permit.request_body_digest?.startsWith("sha256:")) throw new Error("WIRE_MUTATION_UNAUTHORIZED");
    if(!plan.approved_operations.some(op=>op.method===permit.method && op.origin===url.origin &&
      op.path_template===permit.normalized_path &&
      (op.credential_profile_reference??null)===permit.credential_profile_reference &&
      op.body_schema_digest===permit.request_body_digest)) throw new Error("WIRE_OPERATION_NOT_APPROVED");
  }
}
