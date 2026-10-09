/**
 * This file is a frozen-shape local stub boundary ONLY.
 * Main Platform has not finalized or granted any of these capabilities.
 * Do not impersonate the production Host with the synthetic fixture issuer.
 */
export const HOST_PT_CONTRACT_VERSION="host-api-pt-v1-provisional" as const;
export type MainHostAuthorizedContextV1=Readonly<{
 version:typeof HOST_PT_CONTRACT_VERSION;
 organizationId:string;
 agencyClientId:string|null;
 actorId:string;
 delegatedPermissions:readonly string[];
 canonicalTargetId:string;
 environmentId:string;
 ownershipProofId:string;
 scopedPermitId:string;
 permitIssuer:string;
 revocationRevision:number;
 allowedNetworkEgressId:string;
 commercialEntitlementId:string;
}>;
export type HostPtDecisionV1=
 |Readonly<{status:"DENIED";code:string;correlationId:string}>
 |Readonly<{status:"AUTHORIZED";context:MainHostAuthorizedContextV1;correlationId:string}>;
export interface RealMainHostPtAdapterV1 {
 readonly contractVersion:typeof HOST_PT_CONTRACT_VERSION;
 requestAuthorization(request:Readonly<{targetId:string;specificationId:string;scopeFingerprint:string}>):Promise<HostPtDecisionV1>;
 verifyAtOperation(permitId:string,operationKey:string,method:string):Promise<HostPtDecisionV1>;
 revokePermit(permitId:string,reason:string):Promise<void>;
}
export class HostPtUnavailable extends Error{
 readonly code="REAL_MAIN_HOST_CONTRACT_NOT_FROZEN";
 constructor(){super("Main Platform real API PT execution is blocked until Host authority, ownership, revocation and safe egress are implemented.");}
}
/** Intentionally immutable fail-closed behavior: no fake Host permit or production execution. */
export const blockedMainHostPtAdapterV1:RealMainHostPtAdapterV1=Object.freeze({
 contractVersion:HOST_PT_CONTRACT_VERSION,
 async requestAuthorization():Promise<HostPtDecisionV1>{throw new HostPtUnavailable();},
 async verifyAtOperation():Promise<HostPtDecisionV1>{throw new HostPtUnavailable();},
 async revokePermit():Promise<void>{throw new HostPtUnavailable();}
});
/**
 * Phase 07 detectors must consume only the worker-governed authorized fixture
 * execution context and its persisted receipts; direct customer HTTP is not
 * represented by this contract.
 */
export const PT_ENGINE_CONTRACT_VERSION="synthetic-pt-governor-v1" as const;
export type GovernedPtOperationV1=Readonly<{
 jobId:string;
 tenantId:string;
 targetId:string;
 scopeId:string;
 permitId:string;
 fixtureId:"billing-safe-v1";
 specificationId:string;
 specificationVersion:number;
 operationKey:string;
 method:"GET"|"HEAD";
 path:"/status"|"/bills";
 budgetReservationId:string;
 validationLevel:"SYNTHETIC_PT_FIXTURE";
}>;
export type GovernedPtReceiptV1=Readonly<{
 operationKey:string;
 permitHash:string;
 evaluationSequence:number;
 scopeRevision:number;
 responseHash:string|null;
 decision:"ALLOWED"|"DENIED"|"SKIPPED";
 customerNetworkRequests:0;
}>;
