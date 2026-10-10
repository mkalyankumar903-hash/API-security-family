import React,{useEffect,useState} from "react";
import {V13Client,type CommercialSummary} from "../../sdk/src/v13.js";
import {recognizedLocale,localeDirection,count,type Phase12Locale} from "./phase12-locale.js";
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
export function Phase13Workspace({token,targetId}:{token:string;targetId:string}){
 const [data,setData]=useState<CommercialSummary|null>(null);
 const [history,setHistory]=useState<{id:string;units:number;sourceReportId:string}[]>([]);
 const [reconciliation,setReconciliation]=useState<{id:string;state:string}[]>([]);
 const [error,setError]=useState(""),[loading,setLoading]=useState(true);
 const [locale,setLocale]=useState<Phase12Locale>(()=>typeof window==="undefined"?"en":recognizedLocale(new URLSearchParams(window.location.search).get("apiLocale")??navigator.language));
 // QA pseudo-locales, not customer translation claims; keep the evidence/code identifiers verbatim.
 const label=(message:string)=>locale==="en-XA"?"⟦"+message.replace(/[aeiouAEIOU]/g,ch=>ch+ch)+"⟧":locale==="en-XB"?"⟦"+message+"⟧":message;
 useEffect(()=>{
  let active=true;const controller=new AbortController();
  setData(null);setHistory([]);setReconciliation([]);setError("");setLoading(true);
  const sdk=new V13Client({baseUrl:BASE,accessToken:()=>token});
  void Promise.all([sdk.summary(controller.signal),sdk.usage(10,0,controller.signal),
   sdk.reconciliations(10,0,controller.signal)]).then(([summary,usage,recs])=>{
   if(active){setData(summary);setHistory(usage);setReconciliation(recs);}
  }).catch(e=>{if(active)setError(e instanceof Error?e.message:"COMMERCIAL_READ_FAILED");})
   .finally(()=>{if(active)setLoading(false);});
  return()=>{active=false;controller.abort();};
 },[token,targetId]);
 return <section id="phase13-commercial" aria-labelledby="phase13-heading" dir={localeDirection(locale)}>
  <label htmlFor="phase13-locale">{label("Commercial QA locale")}</label>
  <select id="phase13-locale" value={locale} onChange={e=>setLocale(recognizedLocale(e.target.value))}>
   <option value="en">English</option><option value="en-XA">Pseudo-expanded QA</option><option value="en-XB">Pseudo-RTL QA</option>
  </select>
  <h2 id="phase13-heading">{label("Commercial usage & entitlements — Phase 13")}</h2>
  <p>{label("Tenant-scoped observations only. Selected target context:")} <code dir="ltr">{targetId.slice(0,12)}</code>. {label("No live Main Platform Host, payment, invoice, or PT authorization.")}</p>
  {loading&&<p role="status">Loading authorized commercial projection…</p>}
  {error&&<p role="alert" className="error">{error}</p>}
  {data&&<div>
   <p role="status">Host authority: <strong>{data.hostAuthority}</strong>. Commercial production access remains blocked.</p>
   <p>Entitlement: {data.entitlement?.syntheticOnly?"SYNTHETIC TEST FIXTURE":"NOT CONFIGURED"}</p>
   <div style={{overflowX:"auto",maxWidth:"100%"}}><table><caption>Observed report capacity — not a bill or subscription</caption>
    <thead><tr><th scope="col">{label("Feature")}</th><th scope="col">{label("Quota")}</th><th scope="col">{label("Reserved")}</th><th scope="col">{label("Consumed")}</th><th scope="col">{label("Remaining")}</th></tr></thead>
    <tbody><tr><th scope="row">{data.feature}</th><td>{count(data.quota,locale)}</td><td>{count(data.reserved,locale)}</td><td>{count(data.consumed,locale)}</td><td>{count(data.remaining,locale)}</td></tr></tbody>
   </table></div>
   <p>{label("Meter:")} {data.meterUnit}. {label("UTC accounting month:")} {data.monthStart}. {label("Billable: no.")}</p>
   <h3>{label("Immutable local usage ledger")}</h3>
   {history.length===0?<p>No observed commercial usage recorded.</p>:
    <table><thead><tr><th scope="col">Evidence ID</th><th scope="col">Units</th></tr></thead><tbody>
     {history.map(r=><tr key={r.id}><th scope="row"><code>{r.sourceReportId.slice(0,12)}</code></th><td>{r.units}</td></tr>)}
    </tbody></table>}
   <h3>{label("External reconciliation")}</h3>
   {reconciliation.length===0?<p>PENDING_EXTERNAL_AUTHORITY — no independent Host snapshot.</p>:
    <ul>{reconciliation.map(r=><li key={r.id}>{r.state}</li>)}</ul>}
  </div>}
  <small>English UI; existing Phase 12 pseudo-locales remain QA-only. UNKNOWN ≠ SAFE; VERIFIED_FIXED remains Host-owned.</small>
 </section>;
}
