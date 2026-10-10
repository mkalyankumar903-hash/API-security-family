import React,{useEffect,useState} from "react";
const API=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
type Finding={key:string;ruleId:string;source:string;explanation:string;remediation:string};
type Annotation={stable_key:string;version:number;state:string;note:string;created_at:string};
type Branding={displayName:string;reportTitle:string;accentHex:string;version:number};
type Share={shareId:string;expiresAt:string;revokedAt:string|null;createdAt:string};
type History={id:string;status:string;mode:string;created_at:string};
type Comparison={compatibility:"COMPATIBLE"|"INCOMPATIBLE";reason?:string;
 newlyObserved?:string[];stillObserved?:string[];noLongerObserved?:string[];
 evidenceChanged?:string[];limitation?:string};
const states=[
 ["NEEDS_REVIEW","Needs review"],
 ["INVESTIGATING","Investigating"],
 ["REMEDIATION_PLANNED","Remediation planned"],
 ["FIX_CLAIMED","Fix claimed (NOT VERIFIED_FIXED)"],
 ["DEFERRED","Deferred"],
 ["ACCEPTED_FOR_REVIEW","Accepted for further review"]
] as const;
async function fetchJSON<T>(token:string,path:string,body?:unknown,method="GET",key?:string):Promise<T>{
 const response=await fetch(API+path,{method,cache:"no-store",headers:{
  authorization:"Bearer "+token,...(body?{"content-type":"application/json"}:{}),
  ...(key?{"idempotency-key":key}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const result=await response.json() as T&{error?:string};
 if(!response.ok)throw new Error(result.error??"REQUEST_FAILED");
 return result;
}
export function Phase12ReportControls({token,reportId,targetId,findings}:{
 token:string;reportId:string;targetId:string;findings:Finding[]
}){
 const [annotations,setAnnotations]=useState<Annotation[]>([]);
 const [brand,setBrand]=useState<Branding>({displayName:"Organization",reportTitle:"API Security Report",accentHex:"#2457A7",version:0});
 const [displayName,setDisplayName]=useState("Organization"),[title,setTitle]=useState("API Security Report"),[accent,setAccent]=useState("#2457A7");
 const [shares,setShares]=useState<Share[]>([]),[history,setHistory]=useState<History[]>([]);
 const [comparisonId,setComparisonId]=useState(""),[comparison,setComparison]=useState<Comparison|null>(null);
 const [findingKey,setFindingKey]=useState(findings[0]?.key??""),[workflowState,setWorkflowState]=useState("NEEDS_REVIEW");
 const [note,setNote]=useState(""),[lifetime,setLifetime]=useState(3600);
 const [busy,setBusy]=useState(false),[error,setError]=useState(""),[message,setMessage]=useState("");
 const path="/v12/reports/"+encodeURIComponent(reportId);
 async function reload(){
  const [notes,settings,refs,h]=await Promise.all([
   fetchJSON<Annotation[]>(token,path+"/annotations?limit=100"),
   fetchJSON<Branding>(token,"/v12/branding"),
   fetchJSON<Share[]>(token,path+"/shares?limit=100"),
   fetchJSON<History[]>(token,"/v11/api-vapt/targets/"+encodeURIComponent(targetId)+"/history?limit=30")
  ]);
  setAnnotations(notes);setBrand(settings);setDisplayName(settings.displayName);
  setTitle(settings.reportTitle);setAccent(settings.accentHex);setShares(refs);setHistory(h);
 }
 useEffect(()=>{
  let live=true;setAnnotations([]);setShares([]);setComparison(null);setError("");setMessage("");
  setFindingKey(findings[0]?.key??"");
  if(!token||!reportId)return()=>{live=false;};
  const load=async()=>{
   const [notes,settings,refs,h]=await Promise.all([
    fetchJSON<Annotation[]>(token,path+"/annotations?limit=100"),
    fetchJSON<Branding>(token,"/v12/branding"),
    fetchJSON<Share[]>(token,path+"/shares?limit=100"),
    fetchJSON<History[]>(token,"/v11/api-vapt/targets/"+encodeURIComponent(targetId)+"/history?limit=30")
   ]);
   if(live){setAnnotations(notes);setBrand(settings);setDisplayName(settings.displayName);
    setTitle(settings.reportTitle);setAccent(settings.accentHex);setShares(refs);setHistory(h);}
  };
  void load().catch(e=>{if(live)setError(e instanceof Error?e.message:"REQUEST_FAILED");});
  return()=>{live=false;};
 },[token,reportId,targetId,findings[0]?.key]);
 async function action(cb:()=>Promise<string>){
  setBusy(true);setError("");setMessage("");
  try{const text=await cb();setMessage(text);}catch(e){
   setError(e instanceof Error?e.message:"REQUEST_FAILED");
  }finally{setBusy(false);}
 }
 const version=annotations.filter(x=>x.stable_key===findingKey).reduce((n,x)=>Math.max(n,x.version),0);
 return <section aria-labelledby="phase12-controls-title">
  <h3 id="phase12-controls-title">Authorized report workflow</h3>
  {busy&&<p role="status">Saving tenant-scoped workflow data…</p>}
  {error&&<p role="alert" className="error">{error}</p>}
  {message&&<p role="status">{message}</p>}
  <fieldset disabled={busy}><legend>Finding investigation (annotations never alter canonical security evidence)</legend>
   <label htmlFor="v12-finding">Observed finding</label>
   <select id="v12-finding" value={findingKey} onChange={e=>setFindingKey(e.target.value)}>
    <option value="">Select an evidence-backed finding</option>
    {findings.map((f,i)=><option key={f.key+"-"+i} value={f.key}>{f.ruleId} · {f.source}</option>)}
   </select>
   <label htmlFor="v12-state">Customer triage workflow</label>
   <select id="v12-state" value={workflowState} onChange={e=>setWorkflowState(e.target.value)}>
    {states.map(([value,label])=><option key={value} value={value}>{label}</option>)}
   </select>
   <label htmlFor="v12-note">Bounded investigation note</label>
   <textarea id="v12-note" value={note} maxLength={1000} onChange={e=>setNote(e.target.value)} />
   <p>Current annotation version: {version}. FIX_CLAIMED is only a customer note, never VERIFIED_FIXED.</p>
   <button type="button" disabled={!findingKey} onClick={()=>void action(async()=>{
    await fetchJSON(token,path+"/annotations",{stableKey:findingKey,state:workflowState,note,expectedVersion:version},"POST");
    await reload();setNote("");return "Annotation saved as a new immutable workflow version.";
   })}>Save versioned annotation</button>
  </fieldset>
  <h4>Immutable annotation history</h4>
  {annotations.length===0?<p>No customer workflow annotations.</p>:<ul>
   {annotations.slice(0,50).map((x,i)=><li key={x.stable_key+":"+x.version+":"+i}>
    {x.stable_key.slice(0,10)} · v{x.version} · {x.state} · {x.note}
   </li>)}
  </ul>}
  <fieldset disabled={busy}><legend>Controlled tenant branding (not security authority)</legend>
   <label htmlFor="v12-display">Display name</label>
   <input id="v12-display" value={displayName} maxLength={100} onChange={e=>setDisplayName(e.target.value)}/>
   <label htmlFor="v12-title">Report title</label>
   <input id="v12-title" value={title} maxLength={120} onChange={e=>setTitle(e.target.value)}/>
   <label htmlFor="v12-color">Accent color</label>
   <input id="v12-color" type="text" value={accent} pattern="#[a-fA-F0-9]{6}" onChange={e=>setAccent(e.target.value)}/>
   <p>Branding v{brand.version} changes PDF presentation only. Mandatory disclaimers remain.</p>
   <button type="button" onClick={()=>void action(async()=>{
    await fetchJSON(token,"/v12/branding",{displayName,reportTitle:title,accentHex:accent,expectedVersion:brand.version},"PUT");
    await reload();return "Tenant branding saved. New PDFs use the updated presentation.";
   })}>Update report branding</button>
  </fieldset>
  <fieldset disabled={busy}><legend>Authenticated tenant-only report sharing</legend>
   <p>These references never grant public access. Current tenant Bearer authorization is required even with a share ID.</p>
   <label htmlFor="v12-share-life">Share expiration</label>
   <select id="v12-share-life" value={lifetime} onChange={e=>setLifetime(Number(e.target.value))}>
    <option value={300}>5 minutes</option><option value={3600}>1 hour</option>
    <option value={86400}>24 hours</option>
   </select>
   <button type="button" onClick={()=>void action(async()=>{
    await fetchJSON(token,path+"/shares",{durationSeconds:lifetime},"POST","phase12-share-"+crypto.randomUUID());
    await reload();return "Revocable tenant-only reference created.";
   })}>Create restricted share</button>
  </fieldset>
  {shares.length===0?<p>No restricted report shares.</p>:<ul>{shares.map(s=><li key={s.shareId}>
   <code>{s.shareId}</code> · expires {new Date(s.expiresAt).toLocaleString("en",{timeZone:"UTC"})} UTC
   · {s.revokedAt?"Revoked":"Not revoked"}
   {!s.revokedAt&&<button type="button" disabled={busy} onClick={()=>void action(async()=>{
    await fetchJSON(token,"/v12/shares/"+encodeURIComponent(s.shareId)+"/revoke",{},"POST");
    await reload();return "Restricted share revoked.";
   })}>Revoke share</button>}
  </li>)}</ul>}
  <h4>Historical evidence comparison</h4>
  <label htmlFor="v12-historical">Comparison assessment</label>
  <select id="v12-historical" value={comparisonId} onChange={e=>{setComparisonId(e.target.value);setComparison(null);}}>
   <option value="">Select a historical completed run</option>
   {history.filter(x=>x.id!==reportId&&x.status==="COMPLETED").map(x=><option key={x.id} value={x.id}>
    {x.id.slice(0,12)} · {x.mode}</option>)}
  </select>
  <button type="button" disabled={busy||!comparisonId} onClick={()=>void action(async()=>{
   const compared=await fetchJSON<Comparison>(token,"/v11/api-vapt/assessments/"+encodeURIComponent(reportId)+"/compare/"+encodeURIComponent(comparisonId));
   setComparison(compared);return "Historical compatibility checked by existing Phase11 report authority.";
  })}>Compare actual immutable assessments</button>
  {comparison&&<div role="status">
   <p><strong>{comparison.compatibility}</strong> {comparison.reason??""}</p>
   {comparison.compatibility==="COMPATIBLE"&&<p>New {comparison.newlyObserved?.length??0} ·
    Still observed {comparison.stillObserved?.length??0} · No longer observed {comparison.noLongerObserved?.length??0} ·
    Evidence changed {comparison.evidenceChanged?.length??0}</p>}
   <p>No longer observed NEVER establishes VERIFIED_FIXED.</p>
  </div>}
  <p><a href="#vapt11-panel">Controlled reassessment uses the existing signed-scope VAPT authority. Navigate to the Autonomous VAPT workspace.</a></p>
 </section>;
}
