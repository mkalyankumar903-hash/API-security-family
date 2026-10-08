import Ajv from "ajv";

export const MAX_ORDINAL = Number.MAX_SAFE_INTEGER;
export type ProbeMethod = "GET" | "HEAD";
export type ExecutionMode = "SPEC_ONLY" | "READ_ONLY_PROBE" | "CONTROLLED_ACTIVE" | "MUTATING_STAGING";
export type ProbePlan = {
  mode: ExecutionMode;
  methods: string[];
  maxRequests: number;
  approvedOperations?: string[];
  environment?: "PRODUCTION" | "STAGING" | "SYNTHETIC";
  fixtureBoundary?: string;
  cleanupVerification?: boolean;
};
export type PermitDecision =
  | { allowed: true; reason_code: "ALLOWED"; permitId: string; requestOrdinal: number; remainingRequests: number; expiresAt: string; requestDigest: string }
  | { allowed: false; reason_code: "DENIED_POLICY" | "DENIED_BUDGET" | "DENIED_EXPIRED" | "DENIED_BINDING"; permitId?: never };
const nonzero = { type: "integer", minimum: 1, maximum: MAX_ORDINAL };
const nonnegative = { type: "integer", minimum: 0, maximum: MAX_ORDINAL };
export const planSchema = {
  type: "object", additionalProperties: false,
  required: ["mode", "methods", "maxRequests"],
  properties: {
    mode: { enum: ["SPEC_ONLY", "READ_ONLY_PROBE", "CONTROLLED_ACTIVE", "MUTATING_STAGING"] },
    methods: { type: "array", uniqueItems: true, items: { enum: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"] } },
    maxRequests: nonzero,
    approvedOperations: { type: "array", uniqueItems: true, items: { type: "string", minLength: 1 } },
    environment: { enum: ["PRODUCTION", "STAGING", "SYNTHETIC"] },
    fixtureBoundary: { type: "string", minLength: 1 },
    cleanupVerification: { type: "boolean" }
  },
  allOf: [
    { if: { properties: { mode: { const: "SPEC_ONLY" } }, required: ["mode"] }, then: { properties: { methods: { maxItems: 0 } } } },
    { if: { properties: { mode: { enum: ["READ_ONLY_PROBE", "CONTROLLED_ACTIVE"] } }, required: ["mode"] }, then: { properties: { methods: { items: { enum: ["GET", "HEAD"] } } } } },
    { if: { properties: { mode: { const: "MUTATING_STAGING" } }, required: ["mode"] }, then: { required: ["environment", "approvedOperations", "fixtureBoundary", "cleanupVerification"], properties: { environment: { enum: ["STAGING", "SYNTHETIC"] }, approvedOperations: { minItems: 1 }, cleanupVerification: { const: true } } } }
  ]
} as const;
export const permitSchema = {
  oneOf: [
    { type: "object", additionalProperties: false, required: ["allowed", "reason_code", "permitId", "requestOrdinal", "remainingRequests", "expiresAt", "requestDigest"],
      properties: { allowed: { const: true }, reason_code: { const: "ALLOWED" }, permitId: { type: "string", minLength: 1 }, requestOrdinal: nonzero, remainingRequests: nonnegative, expiresAt: { type: "string", minLength: 1 }, requestDigest: { type: "string", pattern: "^[a-f0-9]{64}$" } } },
    { type: "object", additionalProperties: false, required: ["allowed", "reason_code"],
      properties: { allowed: { const: false }, reason_code: { enum: ["DENIED_POLICY", "DENIED_BUDGET", "DENIED_EXPIRED", "DENIED_BINDING"] } } }
  ]
} as const;
const ajv = new Ajv({ allErrors: true, strict: false });
const validatePlanSchema = ajv.compile(planSchema);
const validatePermitSchema = ajv.compile(permitSchema);
export function validatePlan(value: unknown): asserts value is ProbePlan {
  if (!validatePlanSchema(value)) throw new Error("INVALID_PLAN: " + ajv.errorsText(validatePlanSchema.errors));
  const plan = value as ProbePlan;
  if (plan.mode === "MUTATING_STAGING") throw new Error("MUTATING_STAGING_NOT_ENABLED");
  if (plan.mode !== "SPEC_ONLY") throw new Error("LIVE_PROBE_NOT_ENABLED_IN_PHASE_0");
}
export function validatePermit(value: unknown, expected: { budget: number; ordinal: number; requestDigest: string; now: Date }): asserts value is PermitDecision {
  if (!validatePermitSchema(value)) throw new Error("INVALID_PERMIT: " + ajv.errorsText(validatePermitSchema.errors));
  if (!Number.isSafeInteger(expected.budget) || expected.budget < 1 || expected.budget > MAX_ORDINAL || !Number.isSafeInteger(expected.ordinal) || expected.ordinal < 1 || expected.ordinal > expected.budget) throw new Error("INVALID_BUDGET_OR_ORDINAL");
  const permit = value as PermitDecision;
  if (permit.allowed) {
    if (permit.requestOrdinal !== expected.ordinal || permit.requestOrdinal > expected.budget || permit.remainingRequests > expected.budget - expected.ordinal || permit.requestDigest !== expected.requestDigest)
      throw new Error("PERMIT_BINDING_OR_BUDGET_MISMATCH");
    if (!Number.isFinite(Date.parse(permit.expiresAt)) || Date.parse(permit.expiresAt) <= expected.now.getTime()) throw new Error("PERMIT_EXPIRED");
  }
}
export function nextOrdinal(consumed: number, budget: number): number {
  if (!Number.isSafeInteger(consumed) || consumed < 0 || !Number.isSafeInteger(budget) || budget < 1 || budget > MAX_ORDINAL || consumed >= budget) throw new Error("BUDGET_EXHAUSTED");
  return consumed + 1;
}
