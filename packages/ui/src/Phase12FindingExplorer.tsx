import React,{useEffect,useState} from "react";
const URL_BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
type Item={stableKey:string;assessmentId:string;ruleId:string;source:string;impact:string;
 category:string;confidence:string;observation:string;remediation:string;annotationState:string;
 annotationVersion:number;createdAt:string;verifiedFixed:false;customerRuntimeVerified:false};
type Page={schemaVersion:string;targetId:string;limit:number;offset:number;items:Item[];disclaimer:string};
type Evidence={findingKey:string;sourceFingerprint:string;evidenceFingerprint:string;
 specificationFingerprint:string;observation:string;source:string;ruleId:string;
 limitations:string[];verifiedFixed:false;customerRuntimeVerified:false};
async function access<T>(token:string,path:string):Promise<T>{
 const response=await fetch(URL_BASE+path,{cache:"no-store",headers:{authorization:"Bearer "+token}});
 const value=await response.json() as T&{error?:string};
 if(!response.ok)throw new Error(value.error||"AUTHORIZED_EVIDENCE_UNAVAILABLE");
 return value;
}
export function Phase12FindingExplorer({token,targetId}:{token:string;targetId:string}){
 const [source,setSource]=useState(""),[state,setState]=useState(""),[rule,setRule]=useState("");
 const [page,setPage]=useState(0),[rows,setRows]=useState<Item[]>([]);
 const [evidence,setEvidence]=useState<Evidence|null>(null),[selected,setSelected]=useState("");
 const [error,setError]=useState(""),[loading,setLoading]=useState(false);
 useEffect(()=>{setSource("");setState("");setRule("");setPage(0);setSelected("");setEvidence(null);setRows([]);},[token,targetId]);
 useEffect(()=>{let active=true;setRows([]);setError("");setLoading(true);
  const q=new URLSearchParams({targetId,limit:"20",offset:String(page*20)});
  if(source)q.set("source",source);if(state)q.set("annotationState",state);if(rule.trim())q.set("ruleId",rule.trim());
  void access<Page>(token,"/v12/findings?"+q.toString()).then(result=>{
   if(active){setRows(result.items);setLoading(false);}
  }).catch(e=>{if(active){setError(e instanceof Error?e.message:"FINDING_QUERY_FAILED");setLoading(false);}});
  return()=>{active=false;};
 },[token,targetId,source,state,rule,page]);
 useEffect(()=>{let active=true;setEvidence(null);if(!selected)return()=>{active=false;};
  const parts=selected.split("/");
  if(parts.length!==2)return()=>{active=false;};
  void access<Evidence>(token,"/v12/reports/"+encodeURIComponent(parts[0])+"/evidence/"+encodeURIComponent(parts[1])).then(value=>{if(active)setEvidence(value);})
   .catch(e=>{if(active)setError(e instanceof Error?e.message:"EVIDENCE_UNAVAILABLE");});
  return()=>{active=false;};
 },[token,selected]);
 return <section id="phase12-finding-explorer" aria-labelledby="phase12-findings-title">
  <h3 id="phase12-findings-title">Cross-assessment findings explorer</h3>
  <p>Only committed tenant-owned synthetic/specification evidence. No customer runtime verification or VERIFIED_FIXED claims.</p>
  <label htmlFor="phase12-source">Evidence source filter</label>
  <select id="phase12-source" value={source} onChange={e=>{setSource(e.target.value);setPage(0);}}>
   <option value="">All authorized sources</option>
   <option value="SPEC_ONLY">Specification-only observations</option>
   <option value="SYNTHETIC_PT">Isolated synthetic PT</option>
   <option value="RELATED_EVIDENCE">Related evidence</option>
  </select>
  <label htmlFor="phase12-annotation">Finding triage filter</label>
  <select id="phase12-annotation" value={state} onChange={e=>{setState(e.target.value);setPage(0);}}>
   <option value="">All triage states</option>
   <option value="UNANNOTATED">Unannotated</option>
   <option value="NEEDS_REVIEW">Needs review</option>
   <option value="INVESTIGATING">Investigating</option>
   <option value="REMEDIATION_PLANNED">Remediation planned</option>
   <option value="FIX_CLAIMED">Fix claimed — not verified</option>
   <option value="DEFERRED">Deferred</option>
   <option value="ACCEPTED_FOR_REVIEW">Accepted for review</option>
  </select>
  <label htmlFor="phase12-rule">Exact rule ID (optional)</label>
  <input id="phase12-rule" value={rule} maxLength={100} onChange={e=>{setRule(e.target.value);setPage(0);}}/>
  {loading&&<p role="status">Loading tenant-authorized findings…</p>}
  {error&&<p role="alert">{error}</p>}
  {!loading&&rows.length===0&&<p>No findings observed in the current filters. No evidence does NOT prove safety.</p>}
  {rows.length>0&&<table><caption>Evidence-backed filtered findings</caption><thead><tr>
   <th scope="col">Rule</th><th scope="col">Source</th><th scope="col">Impact</th>
   <th scope="col">Triage</th><th scope="col">Evidence</th>
   </tr></thead><tbody>{rows.map(row=><tr key={row.assessmentId+":"+row.stableKey}>
    <th scope="row">{row.ruleId||"UNKNOWN"}</th><td>{row.source}</td><td>{row.impact||"UNKNOWN"}</td>
    <td>{row.annotationState}</td><td><button type="button" onClick={()=>{
      setError("");setSelected(row.assessmentId+"/"+row.stableKey);
    }}>Inspect redacted evidence</button></td></tr>)}</tbody></table>}
  <div className="phase12-page-controls">
   <button type="button" disabled={page===0||loading} onClick={()=>{setPage(x=>x-1);setEvidence(null);setSelected("");}}>Previous</button>
   <span aria-live="polite">Page {page+1}</span>
   <button type="button" disabled={rows.length<20||loading} onClick={()=>{setPage(x=>x+1);setEvidence(null);setSelected("");}}>Next</button>
  </div>
  {evidence&&<article aria-label="Redacted evidence provenance" className="finding">
   <h4>Redacted evidence provenance</h4>
   <p>Rule {evidence.ruleId} · {evidence.source}</p>
   <p>Immutable source fingerprint: <code>{evidence.sourceFingerprint}</code></p>
   <p>Evidence fingerprint: <code>{evidence.evidenceFingerprint}</code></p>
   <p>Specification fingerprint: <code>{evidence.specificationFingerprint}</code></p>
   <p>Observation: {evidence.observation}</p>
   <ul>{evidence.limitations.map((x,i)=><li key={i}>{x}</li>)}</ul>
   <p>Customer runtime verified: NO. Canonical verified fixed: NO.</p>
  </article>}
 </section>;
}
