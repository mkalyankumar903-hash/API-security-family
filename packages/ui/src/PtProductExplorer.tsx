import React,{useCallback,useEffect,useState} from "react";
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
type Listed={id:string;assessment_id:string;target_id:string;rule_id:string;rule_revision:string;fingerprint:string;fixture_profile:string;category:string;impact:string;confidence:string;code:string};
type History={id:string;status:string;error_code:string|null;fixture_profile:string;created_at:string;plan_fingerprint:string};
type Finding={id:string;rule_id:string;description:string;impact:string;confidence:string;remediation:string;operationPath:string;fingerprint:string;
 evidence:{actor:string;path:string;status:number;exposedPaths:string[];cacheControl:string|null}[];verifiedFixed:false};
type Result<T>={items:T[];limit:number;offset:number;hasMore:boolean};
type Diagnostic={notice:string;status:string;rules:{rule_id:string;status:string}[];verifiedFixed:false};
type DisplayReport={status:string;observations:unknown[];coverage:{actualEvaluations:number};limitations:string[];verifiedFixed:false};
async function api<T>(token:string,path:string):Promise<T>{
 const response=await fetch(BASE+path,{headers:{authorization:"Bearer "+token}});
 const body=await response.json() as T&{error?:string};
 if(!response.ok)throw new Error(body.error??"PT_PRODUCT_REQUEST_FAILED");
 return body;
}
export function PtProductExplorer({token,targetId}:{token:string;targetId:string}){
 const [search,setSearch]=useState(""),[ruleId,setRuleId]=useState(""),[impact,setImpact]=useState("");
 const [profile,setProfile]=useState(""),[offset,setOffset]=useState(0),[items,setItems]=useState<Listed[]>([]);
 const [hasMore,setHasMore]=useState(false),[history,setHistory]=useState<History[]>([]);
 const [selected,setSelected]=useState<Finding|null>(null),[report,setReport]=useState<DisplayReport|null>(null);
 const [terminal,setTerminal]=useState<Diagnostic|null>(null),[error,setError]=useState("");
 const [busy,setBusy]=useState(false);
 const load=useCallback(async(page:number)=>{
  if(!targetId)return;
  const q=new URLSearchParams({targetId,limit:"20",offset:String(page)});
  if(search.trim())q.set("search",search.trim());
  if(ruleId)q.set("ruleId",ruleId);
  if(impact)q.set("impact",impact);
  if(profile)q.set("fixtureProfile",profile);
  const [found,previous]=await Promise.all([
   api<Result<Listed>>(token,"/v8/pt/findings?"+q.toString()),
   api<Result<History>>(token,"/v8/pt/history?targetId="+targetId+"&limit=30")]);
  setItems(found.items);setHasMore(found.hasMore);setOffset(page);setHistory(previous.items);
 },[targetId,token,search,ruleId,impact,profile]);
 const work=async(action:()=>Promise<void>)=>{
  setBusy(true);setError("");
  try{await action();}catch(e){setError(e instanceof Error?e.message:"UNKNOWN_ERROR");}
  finally{setBusy(false);}
 };
 useEffect(()=>{
  setItems([]);setSelected(null);setReport(null);setTerminal(null);setHistory([]);setOffset(0);
  if(token&&targetId)void load(0).catch(e=>setError(e instanceof Error?e.message:String(e)));
 // Search controls are submitted explicitly to avoid repeated scanning/projection requests.
 },[token,targetId]);
 const detail=(id:string)=>work(async()=>{
  setSelected(await api<Finding>(token,"/v8/pt/findings/"+id));
  setReport(null);setTerminal(null);
 });
 const view=(run:History)=>work(async()=>{
  setReport(null);setTerminal(null);setSelected(null);
  if(run.status==="COMPLETED")setReport(await api<DisplayReport>(token,"/v7/pt/jobs/"+run.id+"/report"));
  else if(run.status==="FAILED"||run.status==="CANCELLED")
   setTerminal(await api<Diagnostic>(token,"/v8/pt/jobs/"+run.id+"/terminal-coverage"));
  else throw new Error("ASSESSMENT_STILL_RUNNING");
 });
 return <section role="region" aria-label="API PT findings and history">
  <h2>API PT Findings, Evidence, Reports &amp; History</h2>
  <p><strong>ISOLATED SYNTHETIC API PENETRATION TESTING</strong> · NOT CUSTOMER PRODUCTION VULNERABILITY VERIFICATION · REAL HOST AUTHORIZATION UNAVAILABLE.</p>
  <p>Only evidence-backed, completed synthetic observations appear in the findings list. Failed or cancelled runs have a separate diagnostic summary.</p>
  {error&&<p role="alert" className="error">{error}</p>}
  <div className="formgrid">
   <label>Search rules and codes<input aria-label="Findings search" maxLength={80} value={search} onChange={e=>setSearch(e.target.value)}/></label>
   <label>Rule<select aria-label="Findings rule filter" value={ruleId} onChange={e=>setRuleId(e.target.value)}>
    <option value="">All rules</option>
    {["PT-AUTH-ANONYMOUS","PT-AUTH-INVALID","PT-AUTH-EXPIRED","PT-AUTH-REVOKED",
     "PT-BOLA-CROSS-USER","PT-FUNCTION-ROLE","PT-SENSITIVE-FIELD","PT-CONFIDENTIAL-CACHE"].map(x=><option key={x}>{x}</option>)}
   </select></label>
   <label>Potential impact<select aria-label="Findings impact filter" value={impact} onChange={e=>setImpact(e.target.value)}>
    <option value="">All impacts</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option>
   </select></label>
   <label>Fixture profile<select aria-label="Findings fixture filter" value={profile} onChange={e=>setProfile(e.target.value)}>
    <option value="">All versions</option>
    {["SECURE_BASELINE","MISSING_AUTH_ENFORCEMENT","CROSS_USER_ACCESS_WEAKNESS","ROLE_RESTRICTION_WEAKNESS",
     "SENSITIVE_RESPONSE_EXPOSURE","INSECURE_CACHE_POLICY"].map(x=><option key={x}>{x}</option>)}
   </select></label>
  </div>
  <button type="button" disabled={busy} onClick={()=>void work(()=>load(0))}>Search PT findings</button>
  <button type="button" className="secondary" disabled={busy} onClick={()=>void work(()=>load(offset))}>Refresh PT history</button>
  <p>Tenant-scoped completed synthetic observations: {items.length} shown, offset {offset}. Runtime customer verification: UNKNOWN.</p>
  {items.length===0&&<p>No completed synthetic observations match these filters. This does not demonstrate customer safety.</p>}
  {items.map(x=><article className="finding" key={x.id}>
   <h3>{x.rule_id} · {x.impact} · {x.confidence}</h3>
   <p>{x.code} · Fixture {x.fixture_profile} · Assessment {x.assessment_id.slice(0,8)}</p>
   <button type="button" className="secondary" disabled={busy} onClick={()=>void detail(x.id)}>Inspect evidence {x.rule_id}</button>
  </article>)}
  <button type="button" className="secondary" disabled={busy||offset===0} onClick={()=>void work(()=>load(Math.max(0,offset-20)))}>Previous findings</button>
  <button type="button" className="secondary" disabled={busy||!hasMore} onClick={()=>void work(()=>load(offset+20))}>Next findings</button>
  {selected&&<section className="finding" aria-label="Synthetic evidence detail">
   <h3>Evidence — {selected.rule_id}</h3>
   <p>{selected.description} · Potential impact {selected.impact} · Confidence {selected.confidence}</p>
   <p>Expected synthetic policy: {selected.description}</p>
   <p>Operation: GET {selected.operationPath} · Observation fingerprint: <code>{selected.fingerprint}</code></p>
   <p>Remediation: {selected.remediation}</p>
   <ul>{selected.evidence.map((x,i)=><li key={i}>{x.actor} · {x.path} · HTTP {x.status} · Redacted field paths: {x.exposedPaths.join(", ")||"None"} · Cache {x.cacheControl??"not present"}</li>)}</ul>
   <strong>NOT A CONFIRMED CUSTOMER VULNERABILITY. VERIFIED_FIXED: false.</strong>
  </section>}
  <h3>Assessment history</h3>
  {history.map(x=><p key={x.id}>{x.status} · {x.fixture_profile} · {new Date(x.created_at).toLocaleString()} ·
   <button type="button" className="secondary" disabled={busy||!["COMPLETED","FAILED","CANCELLED"].includes(x.status)}
    onClick={()=>void view(x)}>Open {x.status==="COMPLETED"?"report":"diagnostics"} {x.id.slice(0,8)}</button></p>)}
  {report&&<section className="finding" aria-label="Synthetic PT report">
   <h3>Immutable report — {report.status}</h3>
   <p>Governed synthetic evaluations: {report.coverage.actualEvaluations} · Synthetic observations: {report.observations.length} · VERIFIED_FIXED: false.</p>
   <ul>{report.limitations.map(x=><li key={x}>{x}</li>)}</ul>
   <button type="button" onClick={()=>window.print()}>Print synthetic PT report</button>
  </section>}
  {terminal&&<section className="finding" aria-label="Failed PT report diagnostics">
   <h3>Assessment incomplete — {terminal.status}</h3><p>{terminal.notice}</p>
   <ul>{terminal.rules.map(x=><li key={x.rule_id}>{x.rule_id} · {x.status}</li>)}</ul>
   <p>No successful report exists. VERIFIED_FIXED: false.</p>
  </section>}
 </section>;
}
