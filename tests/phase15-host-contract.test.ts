import {test} from "node:test";
import assert from "node:assert/strict";
import {randomBytes,randomUUID} from "node:crypto";
import {CAPABILITIES,CI_AUDIENCE,CI_ISSUER,HOST_ADAPTER_SCHEMA,verifyCISimulatorOnly,signCISimulatorOnly,hostTransportFailure,requireProductionHost,type HostAdapterEnvelope} from "../packages/contracts/src/host-adapter-v15.js";
const tenant=randomUUID(),organization=randomUUID(),other=randomUUID(),eventId=randomUUID();
const now=Math.floor(Date.now()/1000),root=randomBytes(48);
const context={tenantId:tenant,organizationId:organization,clientId:null,capability:"identity" as const,requiredPermission:"plugin:read",now};
const unsigned=():Omit<HostAdapterEnvelope,"signature">=>({schemaVersion:HOST_ADAPTER_SCHEMA,issuer:CI_ISSUER,audience:CI_AUDIENCE,tenantId:tenant,organizationId:organization,
 clientId:null,capability:"identity" as const,eventId,sequence:1,issuedAt:now-1,expiresAt:now+120,permissions:["plugin:read"],payload:{scanningAuthority:false}});
function trusted(){return {root,seen:new Set<string>(),lastSequence:new Map<string,number>()};}
function denied(f:()=>unknown,code:string){assert.throws(f,(error:unknown)=>error instanceof Error&&error.message===code);}
test("Phase15 real Host production root never configured; simulator disabled by default",()=>{
 const old={...process.env};
 try{
  process.env.NODE_ENV="production";process.env.GITHUB_ACTIONS="true";process.env.PHASE15_SIMULATOR_ENABLED="true";
  denied(()=>signCISimulatorOnly(unsigned(),root),"HOST_AUTHORITY_NOT_CONFIGURED");
  denied(()=>verifyCISimulatorOnly({},context,trusted()),"HOST_AUTHORITY_NOT_CONFIGURED");
  denied(()=>requireProductionHost(),"HOST_AUTHORITY_NOT_CONFIGURED");
 }finally{process.env.NODE_ENV=old.NODE_ENV;process.env.GITHUB_ACTIONS=old.GITHUB_ACTIONS;
  process.env.PHASE15_SIMULATOR_ENABLED=old.PHASE15_SIMULATOR_ENABLED;}
});
test("Phase15 CI-only HMAC envelope verifies identity, replay, binding, permission, expiry, canonical authority",()=>{
 const old={NODE_ENV:process.env.NODE_ENV,GITHUB_ACTIONS:process.env.GITHUB_ACTIONS,PHASE15_SIMULATOR_ENABLED:process.env.PHASE15_SIMULATOR_ENABLED};
 try{
  process.env.NODE_ENV="test";process.env.GITHUB_ACTIONS="true";process.env.PHASE15_SIMULATOR_ENABLED="true";
  const signed=(delta:Partial<ReturnType<typeof unsigned>>={})=>signCISimulatorOnly({...unsigned(),...delta},root);
  const safe=trusted();
  assert.equal(verifyCISimulatorOnly(signed(),context,safe).tenantId,tenant);
  denied(()=>verifyCISimulatorOnly(signed(),context,safe),"HOST_REPLAYED_EVENT");
  const rejects:[Partial<ReturnType<typeof unsigned>>,string][]=[
   [{issuer:"forged"},"HOST_UNTRUSTED_ISSUER_OR_AUDIENCE"],
   [{audience:"wrong"},"HOST_UNTRUSTED_ISSUER_OR_AUDIENCE"],
   [{tenantId:other},"HOST_TENANT_OR_ORGANIZATION_MISMATCH"],
   [{organizationId:other},"HOST_TENANT_OR_ORGANIZATION_MISMATCH"],
   [{expiresAt:now-1},"HOST_EXPIRED_OR_INVALID_TIME"],
   [{issuedAt:now+90},"HOST_EXPIRED_OR_INVALID_TIME"],
   [{permissions:[]},"HOST_PERMISSION_DENIED"],
   [{payload:{status:"VERIFIED_FIXED"}},"HOST_CANONICAL_AUTHORITY_FORBIDDEN"],
   [{payload:{scanningAuthority:true}},"HOST_CANONICAL_AUTHORITY_FORBIDDEN"],
   [{schemaVersion:"old" as typeof HOST_ADAPTER_SCHEMA},"HOST_UNSUPPORTED_SCHEMA"]
  ];
  for(const [delta,code] of rejects)denied(()=>verifyCISimulatorOnly(signed(delta),context,trusted()),code);
  denied(()=>verifyCISimulatorOnly({...signed(),signature:"ff".repeat(32)},context,trusted()),"HOST_INVALID_SIGNATURE");
  denied(()=>verifyCISimulatorOnly("{bad-json",context,trusted()),"HOST_INVALID_ENVELOPE");
  denied(()=>verifyCISimulatorOnly(signed({eventId:randomUUID(),sequence:0}),context,trusted()),"HOST_INVALID_SEQUENCE");
  const ordered=trusted();
  verifyCISimulatorOnly(signed({eventId:randomUUID(),sequence:2}),context,ordered);
  denied(()=>verifyCISimulatorOnly(signed({eventId:randomUUID(),sequence:1}),context,ordered),"HOST_OUT_OF_ORDER_EVENT");
  denied(()=>verifyCISimulatorOnly(signed({eventId:randomUUID(),sequence:3}),{...context,clientId:other},trusted()),"HOST_TENANT_OR_ORGANIZATION_MISMATCH");
  denied(()=>verifyCISimulatorOnly(signed({eventId:randomUUID(),sequence:3}),{...context,capability:"event"},trusted()),"HOST_CAPABILITY_MISMATCH");

  denied(()=>verifyCISimulatorOnly(signed(),context,{
   ...trusted(),revokedEvents:new Set([CI_ISSUER+":"+tenant+":"+eventId])
  }),"HOST_REVOKED_AUTHORITY");
  denied(()=>verifyCISimulatorOnly(signed(),context,{
   ...trusted(),revokedContexts:new Set([CI_ISSUER+":"+tenant+":identity"])
  }),"HOST_REVOKED_AUTHORITY");
  denied(()=>verifyCISimulatorOnly(signed({eventId:randomUUID(),capability:"bad-capability" as "identity"}),context,trusted()),"HOST_CAPABILITY_MISMATCH");
  assert.equal(CAPABILITIES.length,11);
 }finally{for(const k of Object.keys(old) as (keyof typeof old)[]){const v=old[k];if(v===undefined)delete process.env[k];else process.env[k]=v;}}
});
test("Phase15 Host HTTP failures always deny and do not synthesize fallback",()=>{
 for(const [code,label] of [[401,"HOST_AUTHENTICATION_DENIED"],[403,"HOST_AUTHENTICATION_DENIED"],[409,"HOST_REVISION_CONFLICT"],[429,"HOST_RATE_LIMITED"],[408,"HOST_UNAVAILABLE"],[500,"HOST_UNAVAILABLE"],[502,"HOST_UNAVAILABLE"],[503,"HOST_UNAVAILABLE"],[504,"HOST_UNAVAILABLE"],[undefined,"HOST_UNAVAILABLE"]] as const)
  denied(()=>hostTransportFailure(code),label);
});
