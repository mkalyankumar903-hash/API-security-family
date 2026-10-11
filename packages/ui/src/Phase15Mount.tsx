/** Read-only provisional mount. Parent supplies identity context, NOT browser-granted authority. */
import React,{useEffect,useState} from "react";
import {V13Client,type CommercialSummary} from "../../sdk/src/v13.js";
export type Phase15MountProps={
 apiOrigin:string;tenantContext:string;sessionRevision:string;
 accessToken:()=>string|Promise<string>;onError?:(code:string)=>void;
};
const ID=/^[a-f0-9-]{36}$/i;
function Phase15MountInner({apiOrigin,tenantContext,sessionRevision,accessToken,onError}:Phase15MountProps){
 const [summary,setSummary]=useState<CommercialSummary|null>(null);
 const [state,setState]=useState<"loading"|"ready"|"denied">("loading");
 const [code,setCode]=useState("");
 useEffect(()=>{
  let active=true;const abort=new AbortController();
  setSummary(null);setCode("");setState("loading");
  if(!ID.test(tenantContext)){setCode("INVALID_TENANT_CONTEXT");setState("denied");return()=>abort.abort();}
  let sdk:V13Client;
  try{sdk=new V13Client({baseUrl:apiOrigin,accessToken,timeoutMs:10000,maxRetries:1});}
  catch{setCode("HOST_AUTHORITY_NOT_CONFIGURED");setState("denied");return()=>abort.abort();}
  void Promise.all([sdk.capabilities(abort.signal),sdk.summary(abort.signal)]).then(([caps,data])=>{
   if(!active)return;
   if(caps.scanningAuthority!==false||data.hostAuthority!=="HOST_AUTHORITY_NOT_CONFIGURED"||data.tenantContext!==tenantContext)
    throw new Error("HOST_AUTHORITY_NOT_CONFIGURED");
   setSummary(data);setState("ready");
  }).catch(()=>{
   if(active){setCode("HOST_AUTHORITY_NOT_CONFIGURED");setState("denied");onError?.("HOST_AUTHORITY_NOT_CONFIGURED");}
  });
  return()=>{active=false;abort.abort();};
 },[tenantContext,sessionRevision,apiOrigin,accessToken,onError]);
 return <section aria-label="LumicSec API plugin read-only" data-phase15-mount="read-only">
  <h2>LumicSec API Security</h2>
  <p>Isolated integration preview. No production Host login, permits, billing or VERIFIED_FIXED authority.</p>
  {state==="loading"&&<p role="status">Loading authorized read-only projection…</p>}
  {state==="denied"&&<p role="alert">{code||"HOST_AUTHORITY_NOT_CONFIGURED"}</p>}
  {state==="ready"&&summary&&<div role="status">
   <p>Production Host authority: {summary.hostAuthority}</p>
   <p>Read-only usage: {summary.consumed} consumed, {summary.remaining} remaining (synthetic projection, not a bill).</p>
  </div>}
 </section>;
}

/** Renderer-error containment: never expose error messages or privilege-bearing fallback. */
export class Phase15ErrorBoundary extends React.Component<
 React.PropsWithChildren<{onError?:(code:string)=>void}>,{failed:boolean}
>{
 state={failed:false};
 static getDerivedStateFromError(_error:unknown){return {failed:true};}
 componentDidCatch(){this.props.onError?.("HOST_AUTHORITY_NOT_CONFIGURED");}
 render(){
  if(this.state.failed)return <section role="alert" data-phase15-boundary-error="true">HOST_AUTHORITY_NOT_CONFIGURED</section>;
  return this.props.children;
 }
}
export function Phase15Mount(props:Phase15MountProps){
 // React passive effects run after commit: remount synchronously on an authority-context change.
 // This prevents one-frame stale read-only tenant data and resets a previously failed boundary.
 const authorityKey=[props.apiOrigin,props.tenantContext,props.sessionRevision].join("\u0000");
 return <Phase15ErrorBoundary key={authorityKey} onError={props.onError}><Phase15MountInner {...props}/></Phase15ErrorBoundary>;
}
