import React,{useCallback,useEffect,useState} from "react";

const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
type Version={specificationId:string;version:number;format:string;normalizedFingerprint:string;coverage:string};
type Job={id:string;status:string;engineVersion:string;specificationId?:string;errorCode?:string;specificationVersion?:number};
type Finding={id:string;ruleId:string;ruleRevision:string;fingerprint:string;operationKey:string|null;category:string;
 impact:string;confidence:string;potentialImpact:string;explanation:string;remediation:string;pointer:string;
 evidence:{kind:string;pointer:string;facts:Record<string,unknown>}};
type Coverage={ruleId:string;revision:string;status:string;reason:string|null;matches:number;applicableOperations:number};
type Report={assessmentId:string;engineVersion:string;specificationVersion:number;observationCount:number;operationsAssessed:number;
 observations:Finding[];coverage:Coverage[];warnings:string[];limitations:string[];runtimeValidation:false;confirmedVulnerabilities:[]};
type Rule={id:string;name:string;impact:string;formats:string[];unsupported?:string;availability:string};
type Comparison={comparable:boolean;reason:string|null;counts:{newlyObserved:number;noLongerObserved:number;stillObserved:number;changed:number};
 newlyObserved:Finding[];noLongerObserved:Finding[];stillObserved:Finding[];changed:Finding[];limitation?:string;truncated:boolean};
async function api<T>(token:string,path:string,method="GET",data?:unknown,headers:Record<string,string>={}):Promise<T>{
 const response=await fetch(BASE+path,{method,headers:{Authorization:"Bearer "+token,"Content-Type":"application/json",...headers},
  ...(data!==undefined?{body:JSON.stringify(data)}:{})});
 const payload:unknown=await response.json();
 if(!response.ok)throw new Error((payload as {error?:string}).error??"API_REQUEST_FAILED");
 return payload as T;
}
export function InventoryDetection({token,targetId,active}:{token:string;targetId:string;active:boolean}){
 const [versions,setVersions]=useState<Version[]>([]),[selected,setSelected]=useState("");
 const [rules,setRules]=useState<Rule[]>([]),[history,setHistory]=useState<Job[]>([]),[job,setJob]=useState<Job|null>(null);
 const [findings,setFindings]=useState<Finding[]>([]),[report,setReport]=useState<Report|null>(null);
 const [coverage,setCoverage]=useState<Coverage[]>([]),[detail,setDetail]=useState<Finding|null>(null);
 const [impact,setImpact]=useState(""),[category,setCategory]=useState(""),[confidence,setConfidence]=useState("");
 const [ruleKey,setRuleKey]=useState(""),[operationKey,setOperationKey]=useState(""),[search,setSearch]=useState("");
 const [offset,setOffset]=useState(0),[from,setFrom]=useState(""),[to,setTo]=useState("");
 const [comparison,setComparison]=useState<Comparison|null>(null);
 const [busy,setBusy]=useState(false),[error,setError]=useState(""),[loading,setLoading]=useState(true);
 const refresh=useCallback(async()=>{
  const [v,h,r]=await Promise.all([
   api<Version[]>(token,"/v2/targets/"+targetId+"/specifications?limit=100"),
   api<Job[]>(token,"/v3/targets/"+targetId+"/assessments?limit=100"),
   api<Rule[]>(token,"/v3/detection/rules?limit=100")]);
  setVersions(v);setHistory(h);setRules(r);
  setSelected(old=>v.some(x=>x.specificationId===old)?old:v[0]?.specificationId??"");
  setFrom(old=>h.some(x=>x.id===old)?old:h[1]?.id??"");
  setTo(old=>h.some(x=>x.id===old)?old:h[0]?.id??"");
 },[targetId,token]);
 useEffect(()=>{let live=true;setLoading(true);setError("");setJob(null);setReport(null);setDetail(null);
  void refresh().catch(e=>{if(live)setError(e.message);}).finally(()=>{if(live)setLoading(false);});
  return()=>{live=false;};
 },[refresh]);
 useEffect(()=>{
  if(!job||!["QUEUED","PROCESSING"].includes(job.status))return;
  let live=true;
  const poll=()=>void api<Job>(token,"/v3/assessments/"+job.id).then(x=>{if(live)setJob(x);})
   .catch(e=>{if(live)setError(e.message);});
  poll();const timer=setInterval(poll,1200);return()=>{live=false;clearInterval(timer);};
 },[job?.id,job?.status,token]);
 useEffect(()=>{let live=true;setReport(null);setCoverage([]);setFindings([]);setDetail(null);
  if(job?.status==="COMPLETED"){
   void Promise.all([
    api<Report>(token,"/v3/assessments/"+job.id+"/report"),
    api<Finding[]>(token,"/v3/assessments/"+job.id+"/findings?limit=100&offset=0"),
    api<{coverage:Coverage[]}>(token,"/v3/assessments/"+job.id+"/coverage")
   ]).then(([r,f,c])=>{if(live){setReport(r);setFindings(f);setCoverage(c.coverage);}}).catch(e=>{if(live)setError(e.message);});
  }return()=>{live=false;};
 },[job?.id,job?.status,token]);
 useEffect(()=>{if(!job||job.status!=="COMPLETED")return;let live=true;
  const q=new URLSearchParams({limit:"100",offset:String(offset)});if(impact)q.set("impact",impact);if(category)q.set("category",category);if(confidence)q.set("confidence",confidence);
  if(ruleKey)q.set("ruleId",ruleKey);if(operationKey)q.set("operationKey",operationKey);
  void api<Finding[]>(token,"/v3/assessments/"+job.id+"/findings?"+q).then(r=>{if(live)setFindings(r);}).catch(e=>{if(live)setError(e.message);});
  return()=>{live=false;};
 },[job?.id,job?.status,impact,category,confidence,ruleKey,operationKey,offset,token]);
 async function run(fn:()=>Promise<void>){setBusy(true);setError("");try{await fn();}catch(e){setError(e instanceof Error?e.message:"UNKNOWN_ERROR");}finally{setBusy(false);}}
 async function start(){
  if(!selected||!active)return;
  await run(async()=>{
   const j=await api<Job>(token,"/v3/targets/"+targetId+"/assessments","POST",
    {specificationId:selected,mode:"SPEC_ONLY",engineVersion:"inventory-v1"},{"idempotency-key":"detection-"+crypto.randomUUID()});
   setJob(j);setComparison(null);setImpact("");setCategory("");setConfidence("");setRuleKey("");setOperationKey("");setOffset(0);await refresh();setFrom(history[0]?.id??"");setTo(j.id);
  });
 }
 async function openFinding(f:Finding){
  if(!job)return;
  await run(async()=>{const r=await api<Finding>(token,"/v3/assessments/"+job.id+"/findings/"+f.id);setDetail(r);});
 }
 async function compare(){
  if(!from||!to||from===to)return;
  await run(async()=>{
   setComparison(await api<Comparison>(token,"/v3/targets/"+targetId+"/assessments/compare","POST",{fromAssessmentId:from,toAssessmentId:to}));
  });
 }
 function downloadReport(){
  if(!report)return;
  const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob),link=document.createElement("a");
  link.href=url;link.download="lumicsec-api-assessment-"+report.assessmentId+".json";
  link.click();URL.revokeObjectURL(url);
 }
 const visible=findings.filter(f=>!search||[f.ruleId,f.operationKey??"",f.category].some(x=>x.toLowerCase().includes(search.toLowerCase())));
 const ruleChoices=[...new Set((report?.observations??[]).map(f=>f.ruleId))].sort();
 const operationChoices=[...new Set((report?.observations??[]).map(f=>f.operationKey).filter((v):v is string=>!!v))].sort();
 return <section aria-label="Deterministic API detection">
  <h2>Phase 3 · Deterministic API security detection</h2>
  <p>Real persisted SPEC_ONLY observations from imported inventory. No API traffic, live vulnerability verification or Host authority.</p>
  {loading&&<p role="status">Loading detection capabilities and assessment history…</p>}
  {error&&<p role="alert" className="error">{error}</p>}
  <button className="secondary" disabled={busy} onClick={()=>void run(refresh)}>Refresh imported versions &amp; history</button>
  <label htmlFor="detection-version">Specification version for deterministic assessment</label>
  <select id="detection-version" value={selected} onChange={e=>setSelected(e.target.value)}>
   <option value="">Choose imported version</option>{versions.map(v=><option key={v.specificationId} value={v.specificationId}>v{v.version} · {v.format} · {v.coverage}</option>)}
  </select>
  <p>{rules.filter(r=>!r.unsupported).length} implemented catalog rules · {rules.filter(r=>!!r.unsupported).length} explicitly unsupported; format applicability is assessed per rule.</p>
  <details><summary>Detection capabilities and limitations</summary><table><thead><tr><th>Rule</th><th>Impact candidate</th><th>Applicability</th></tr></thead><tbody>
  {rules.map(r=><tr key={r.id}><td>{r.name} <code>{r.id}</code></td><td>{r.impact}</td><td>{r.unsupported??r.formats.join(", ")}</td></tr>)}</tbody></table></details>
  <button disabled={busy||!selected||!active} onClick={()=>void start()}>Start deterministic SPEC_ONLY assessment</button>
  {!active&&<p>Target is not ACTIVE: assessment submission is prohibited.</p>}
  <h3>Persisted assessment history</h3>
  {history.length===0&&<p>No deterministic assessments have been recorded for this target.</p>}
  <table><thead><tr><th>Version</th><th>Status</th><th>Open</th></tr></thead><tbody>{history.map(h=><tr key={h.id}><td>v{h.specificationVersion??"?"}</td><td>{h.status}</td><td><button className="secondary" onClick={()=>setJob(h)}>Open assessment</button></td></tr>)}</tbody></table>
  {job&&<><h3>Assessment execution</h3><p role="status">Deterministic assessment status: <strong>{job.status}</strong></p>
   {["QUEUED","PROCESSING"].includes(job.status)&&<button className="secondary" disabled={busy} onClick={()=>void run(async()=>{
    const r=await api<Job>(token,"/v3/assessments/"+job.id+"/cancel","POST");setJob(r);await refresh();
   })}>Cancel assessment</button>}
   {job.status==="FAILED"&&<p role="alert">Processing failed: {job.errorCode??"SAFE_INTERNAL_ERROR"}</p>}
   {job.status==="CANCELLED"&&<p>Cancelled. No authoritative detection report was published.</p>}
  </>}
  {report&&<><h3>Evidence-backed assessment report</h3>
   <p>{report.operationsAssessed} operations analyzed · {report.observationCount} specification observations · Runtime verification not performed.</p>
   <p>{report.observationCount===0?"No observations detected in available declarations. API safety remains UNKNOWN.":"Every observation requires review and potential runtime verification."}</p>
   <button className="secondary" onClick={downloadReport}>Download immutable JSON report</button>
   <h4>Rule execution coverage</h4>
   <table><thead><tr><th>Rule</th><th>Execution</th><th>Matches</th><th>Skip reason</th></tr></thead><tbody>{coverage.map(c=><tr key={c.ruleId}>
    <td>{c.ruleId}</td><td>{c.status}</td><td>{c.matches}</td><td>{c.reason??"—"}</td>
   </tr>)}</tbody></table>
   <h4>Findings explorer</h4>
   <div className="formgrid">
    <label>Severity / potential impact<select value={impact} onChange={e=>{setImpact(e.target.value);setOffset(0);}}><option value="">All</option>{["INFORMATIONAL","LOW","MEDIUM","HIGH"].map(x=><option key={x}>{x}</option>)}</select></label>
    <label>Category<select value={category} onChange={e=>{setCategory(e.target.value);setOffset(0);}}><option value="">All</option>{["AUTH","REQUEST","RESPONSE","TRANSPORT","METADATA"].map(x=><option key={x}>{x}</option>)}</select></label>
    <label>Evidence confidence<select value={confidence} onChange={e=>{setConfidence(e.target.value);setOffset(0);}}><option value="">All</option>{["HIGH","MEDIUM","LOW"].map(x=><option key={x}>{x}</option>)}</select></label>
    <label>Detection rule<select value={ruleKey} onChange={e=>{setRuleKey(e.target.value);setOffset(0);}}><option value="">All</option>{ruleChoices.map(x=><option key={x}>{x}</option>)}</select></label>
    <label>Operation<select value={operationKey} onChange={e=>{setOperationKey(e.target.value);setOffset(0);}}><option value="">All</option>{operationChoices.map(x=><option key={x}>{x}</option>)}</select></label>
    <label>Rule or operation search<input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Rule ID or operation"/></label>
   </div>
   <table><thead><tr><th>Rule</th><th>Operation</th><th>Impact</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>{visible.map(f=><tr key={f.id}>
    <td>{f.ruleId}</td><td>{f.operationKey??"Specification-wide"}</td><td>{f.impact}</td><td>{f.confidence}</td>
    <td><button className="secondary" onClick={()=>void openFinding(f)}>Inspect evidence</button></td>
   </tr>)}</tbody></table>
   <button className="secondary" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-100))}>Previous findings</button>
   <button className="secondary" disabled={findings.length<100} onClick={()=>setOffset(offset+100)}>Next findings</button>
   {detail&&<article className="finding"><h4>{detail.ruleId} · Evidence detail</h4><p>{detail.explanation}</p>
    <p>Potential impact: {detail.potentialImpact} · {detail.impact} / confidence {detail.confidence}</p>
    <p>Source pointer: <code>{detail.pointer}</code></p><pre>{JSON.stringify(detail.evidence,null,2)}</pre>
    <p>Remediation guidance: {detail.remediation}</p><p>SPEC_OBSERVATION · Runtime verification required · Not VERIFIED_FIXED</p></article>}
   <h4>Coverage gaps and unknowns</h4>
   <ul>{[...report.warnings,...report.limitations].map((x,i)=><li key={i}>{x}</li>)}</ul>
  </>}
  <h3>Cross-version assessment comparison</h3>
  <div className="formgrid"><label>Baseline completed assessment<select value={from} onChange={e=>setFrom(e.target.value)}><option value="">Select baseline</option>{history.filter(x=>x.status==="COMPLETED").map(x=><option key={x.id} value={x.id}>v{x.specificationVersion} · {x.id.slice(0,8)}</option>)}</select></label>
   <label>New completed assessment<select value={to} onChange={e=>setTo(e.target.value)}><option value="">Select changed</option>{history.filter(x=>x.status==="COMPLETED").map(x=><option key={x.id} value={x.id}>v{x.specificationVersion} · {x.id.slice(0,8)}</option>)}</select></label></div>
  <button disabled={busy||!from||!to||from===to} onClick={()=>void compare()}>Compare assessment observations</button>
  {comparison&&<article className="finding"><h4>Evidence-aware comparison</h4>
   {comparison.comparable?<><p>New {comparison.counts.newlyObserved} · No longer documented {comparison.counts.noLongerObserved} · Still observed {comparison.counts.stillObserved} · Changed {comparison.counts.changed}</p>
    <ul>{comparison.newlyObserved.map(f=><li key={f.fingerprint}>New: {f.ruleId} {f.operationKey}</li>)}
    {comparison.noLongerObserved.map(f=><li key={f.fingerprint}>No longer observed: {f.ruleId} {f.operationKey}</li>)}
    {comparison.changed.map(f=><li key={f.fingerprint}>Changed evidence: {f.ruleId} {f.operationKey}</li>)}</ul>
   </>:<p>Cannot compare: {comparison.reason}</p>}
   <p>Disappearance from a specification does NOT mean VERIFIED_FIXED; documentation, applicability or runtime behavior may differ.</p>
   {comparison.truncated&&<p>Comparison preview bounded to 100 observations per category.</p>}
  </article>}
 </section>;
}
