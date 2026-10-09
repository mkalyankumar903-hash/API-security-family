import {SpecDiscoveryExplorer} from "./SpecDiscoveryExplorer.js";
import {InventoryDetection} from "./InventoryDetection.js";
import {AuthFixtureAssessment} from "./AuthFixtureAssessment.js";
import {TargetOnboarding} from "./TargetOnboarding.js";
import {UnifiedAssessment} from "./UnifiedAssessment.js";
import {PtConsole} from "./PtConsole.js";
import React, { useEffect, useState } from "react";
const API_BASE = (typeof import.meta.env === "object" && import.meta.env.VITE_API_BASE) || "http://127.0.0.1:3001";
type Target = {id:string;name:string;base_url:string;environment:string;lifecycle:string;revision:number;ownership_status:string};
type Specification = {id:string;filename:string;fingerprint:string;operationCount?:number};
type Operation = {key:string;method:string;path:string};
type Job = {id:string;status:string;errorCode?:string};
type Observation = {id:string;ruleId:string;operationKey:string|null;category:string;explanation:string;remediation:string;evidenceId:string;reviewRequired:boolean};
type Report = {assessmentId:string;mode:string;operationsAssessed:number;observationCount:number;observations:Observation[];rulesExecuted:{id:string}[];limitations:string[];coverage:{level:string;runtimeValidation:boolean}};
async function call<T>(token:string, path:string, options?: RequestInit):Promise<T> {
  const result=await fetch(API_BASE + path,{...options,headers:{"Authorization":"Bearer " + token,"Content-Type":"application/json",...(options?.headers||{})}});
  const data:unknown=await result.json();
  if (!result.ok) throw new Error((data as {error?:string}).error || "REQUEST_FAILED");
  return data as T;
}
export function AssessmentApp({initialToken}:{initialToken?:string}) {
  const [token,setToken]=useState(initialToken ?? ((typeof import.meta.env === "object" && import.meta.env.VITE_DEV_TOKEN) || ""));
  const [targets,setTargets]=useState<Target[]>([]);
  const [search,setSearch]=useState("");
  const [lifecycleFilter,setLifecycleFilter]=useState("");
  const [environmentFilter,setEnvironmentFilter]=useState("");
  const [offset,setOffset]=useState(0);
  const [targetId,setTargetId]=useState("");
  const [name,setName]=useState("");
  const [baseUrl,setBaseUrl]=useState("");
  const [environment,setEnvironment]=useState("SYNTHETIC");
  const [specs,setSpecs]=useState<Specification[]>([]);
  const [specId,setSpecId]=useState("");
  const [ops,setOps]=useState<Operation[]>([]);
  const [job,setJob]=useState<Job|null>(null);
  const [findings,setFindings]=useState<Observation[]>([]);
  const [report,setReport]=useState<Report|null>(null);
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const [loading,setLoading]=useState(true);
  function attempt<T>(fn:()=>Promise<T>) { setBusy(true);setError("");return fn().catch(e=>{setError(e instanceof Error?e.message:"UNKNOWN_ERROR");return null;}).finally(()=>setBusy(false)); }
  async function reloadTargets(){
    const query=new URLSearchParams({limit:"20",offset:String(offset)});
    if(search)query.set("search",search);
    if(lifecycleFilter)query.set("lifecycle",lifecycleFilter);
    if(environmentFilter)query.set("environment",environmentFilter);
    const result=await call<Target[]>(token,"/v1/targets?"+query);
    setTargets(result);
  }
  useEffect(()=> {
    let live=true; setLoading(true);setError("");
    if (!token) {setTargets([]);setLoading(false);return;}
    const query=new URLSearchParams({limit:"20",offset:String(offset)});
    if(search)query.set("search",search);
    if(lifecycleFilter)query.set("lifecycle",lifecycleFilter);
    if(environmentFilter)query.set("environment",environmentFilter);
    void call<Target[]>(token,"/v1/targets?"+query).then(r=>{if(live)setTargets(r);}).catch(e=>{if(live){setTargets([]);setTargetId("");setError(e instanceof Error?e.message:"REQUEST_FAILED");}}).finally(()=>{if(live)setLoading(false);});
    return ()=>{live=false;};
  },[token,search,lifecycleFilter,environmentFilter,offset]);
  useEffect(()=>{
    let live=true;
    setSpecs([]);setOps([]);setSpecId("");setJob(null);setReport(null);setFindings([]);
    if(targetId) void call<Specification[]>(token,"/v1/targets/"+targetId+"/specifications").then(s=>{if(live){setSpecs(s);if(s[0])setSpecId(s[0].id);}}).catch(e=>{if(live)setError(e.message);});
    return ()=>{live=false;};
  },[targetId,token]);
  useEffect(()=>{
    let live=true;setOps([]);
    if(specId)void call<Operation[]>(token,"/v1/specifications/"+specId+"/operations?limit=100").then(r=>{if(live)setOps(r);}).catch(e=>{if(live)setError(e.message);});
    return ()=>{live=false;};
  },[specId,token]);
  useEffect(()=>{
    if(!job || !["QUEUED","PROCESSING"].includes(job.status)) return;
    let live=true;
    const update=()=>void call<Job>(token,"/v1/assessments/"+job.id).then(r=>{if(live)setJob(r);}).catch(e=>{if(live)setError(e.message);});
    update();const interval=setInterval(update,1200);
    return ()=>{live=false;clearInterval(interval);};
  },[job?.id,job?.status,token]);
  useEffect(()=>{
    let live=true;
    setReport(null);setFindings([]);
    if(job?.status==="COMPLETED") {
      void Promise.all([call<Report>(token,"/v1/assessments/"+job.id+"/report"),call<Observation[]>(token,"/v1/assessments/"+job.id+"/findings")]).then(([r,f])=>{if(live){setReport(r);setFindings(f);}}).catch(e=>{if(live)setError(e.message);});
    }
    return()=>{live=false;};
  },[job?.id,job?.status,token]);
  async function createTarget(event:React.FormEvent){
    event.preventDefault();
    await attempt(async()=>{
      const r=await call<Target>(token,"/v1/targets",{method:"POST",body:JSON.stringify({name,baseUrl,environment})});
      setSearch("");setLifecycleFilter("");setEnvironmentFilter("");setOffset(0);
      setTargets(s=>[r,...s]);setTargetId(r.id);setName("");setBaseUrl("");
    });
  }
  async function upload(event:React.ChangeEvent<HTMLInputElement>){
    const file=event.target.files?.[0];if(!file || !targetId)return;
    await attempt(async()=>{
      if(file.size>1048576)throw new Error("FILE_TOO_LARGE");
      const content=await file.text();
      const result=await call<Specification>(token,"/v1/targets/"+targetId+"/specifications",{method:"POST",body:JSON.stringify({filename:file.name,content})});
      setSpecs(s=>[result,...s]);setSpecId(result.id);
    });
    event.target.value="";
  }
  async function startAssessment(){
    if(!targetId||!specId||targets.find(t=>t.id===targetId)?.lifecycle!=="ACTIVE")return;
    await attempt(async()=>{
      const key="spec-"+crypto.randomUUID();
      const result=await call<Job>(token,"/v1/targets/"+targetId+"/assessments",{method:"POST",headers:{"idempotency-key":key},body:JSON.stringify({specificationId:specId,mode:"SPEC_ONLY"})});
      setJob(result);setReport(null);
    });
  }
  async function cancel(){
    if(!job)return;
    await attempt(async()=>{const r=await call<Job>(token,"/v1/assessments/"+job.id+"/cancel",{method:"POST"});setJob({...job,status:r.status});});
  }
  return <main className="container">
    <header><div><small>LUMICSEC / API SECURITY FAMILY</small><h1>API Security Assessment</h1><p>Evidence-based OpenAPI analysis · SPEC_ONLY · No live network scanning</p></div><strong className="tag">Phase 05 · Unified offline and synthetic assessment · No Host authority</strong></header>
    <section><label htmlFor="devtoken">Synthetic development token (never a production login)</label><input id="devtoken" value={token} onChange={e=>setToken(e.target.value)} type="password" autoComplete="off" placeholder="Local development token"/></section>
    {loading && <p role="status">Loading targets…</p>}
    {error && <p role="alert" className="error">{error === "PERMISSION_DENIED" || error === "UNAUTHORIZED" ? "Access denied: "+error : error}</p>}
    <section><h2>1. API targets</h2>
      {!loading && targets.length===0 && <p>No API targets registered yet.</p>}
      <div className="formgrid">
        <label>Search targets<input value={search} onChange={e=>{setSearch(e.target.value);setOffset(0);}} placeholder="Search by target or hostname"/></label>
        <label>Filter lifecycle<select value={lifecycleFilter} onChange={e=>{setLifecycleFilter(e.target.value);setOffset(0);}}><option value="">All lifecycle states</option>{["ACTIVE","SUSPENDED","REVOKED","ARCHIVED"].map(s=><option key={s}>{s}</option>)}</select></label>
        <label>Filter environment<select value={environmentFilter} onChange={e=>{setEnvironmentFilter(e.target.value);setOffset(0);}}><option value="">All environments</option>{["SYNTHETIC","STAGING","PRODUCTION"].map(s=><option key={s}>{s}</option>)}</select></label>
      </div>
      <button className="secondary" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-20))}>Previous targets page</button>
      <button className="secondary" disabled={targets.length<20} onClick={()=>setOffset(offset+20)}>Next targets page</button>
      <label htmlFor="target">Select target</label><select id="target" value={targetId} onChange={e=>setTargetId(e.target.value)}><option value="">Select an authorized API target</option>{targets.map(t=><option key={t.id} value={t.id}>{t.name} · {t.environment}</option>)}</select>
      <form onSubmit={e=>void createTarget(e)}><div className="formgrid"><label>Target name<input required maxLength={120} value={name} onChange={e=>setName(e.target.value)} placeholder="Payments API"/></label><label>HTTPS base URL<input required type="url" value={baseUrl} onChange={e=>setBaseUrl(e.target.value)} placeholder="https://api.example.invalid"/></label><label>Environment<select value={environment} onChange={e=>setEnvironment(e.target.value)}><option>SYNTHETIC</option><option>STAGING</option><option>PRODUCTION</option></select></label></div><button disabled={busy||!token} type="submit">Register target</button></form>
    </section>
    <UnifiedAssessment token={token} targetId={targetId}/>
    {targetId&&<PtConsole key={"pt6-"+targetId+token} token={token} targetId={targetId} active={targets.find(t=>t.id===targetId)?.lifecycle==="ACTIVE"}/>}
    {targetId&&<TargetOnboarding key={targetId+token} token={token} targetId={targetId} onChanged={reloadTargets}/>}
    {targetId&&<SpecDiscoveryExplorer key={"discovery-"+targetId+token} token={token} targetId={targetId} active={targets.find(t=>t.id===targetId)?.lifecycle==="ACTIVE"} onSelected={async id=>{
      const updated=await call<Specification[]>(token,"/v1/targets/"+targetId+"/specifications");
      setSpecs(updated);setSpecId(id);
    }}/>}
    {targetId&&<InventoryDetection key={"detect-"+targetId+token} token={token} targetId={targetId} active={targets.find(t=>t.id===targetId)?.lifecycle==="ACTIVE"}/>}
    {targetId&&<AuthFixtureAssessment key={"auth-"+targetId+token} token={token} targetId={targetId} active={targets.find(t=>t.id===targetId)?.lifecycle==="ACTIVE"} revision={targets.find(t=>t.id===targetId)?.revision??1}/>}
    {targetId&&<section><h2>2. OpenAPI specification</h2><p>Upload OpenAPI 3.1 or Swagger 2.0 JSON/YAML, up to 1 MiB. No remote refs are fetched.</p>
      <label htmlFor="specfile">Specification file</label><input id="specfile" type="file" accept=".json,.yaml,.yml" disabled={busy||targets.find(t=>t.id===targetId)?.lifecycle!=="ACTIVE"} onChange={e=>void upload(e)}/>
      <label htmlFor="spec">Select specification</label><select id="spec" value={specId} onChange={e=>setSpecId(e.target.value)}><option value="">Choose uploaded specification</option>{specs.map(s=><option key={s.id} value={s.id}>{s.filename} ({s.fingerprint.slice(0,12)})</option>)}</select>
      <h3>Normalized operations</h3>{specId&&ops.length===0&&<p>No operations recorded.</p>}
      <table><thead><tr><th>Method</th><th>Path</th></tr></thead><tbody>{ops.map(op=><tr key={op.key}><td>{op.method}</td><td><code>{op.path}</code></td></tr>)}</tbody></table>
    </section>}
    {specId&&<section><h2>3. Assessment</h2><p>SPEC_ONLY examines the stored document, not a live endpoint.</p>
      <button disabled={busy||targets.find(t=>t.id===targetId)?.lifecycle!=="ACTIVE"} onClick={()=>void startAssessment()}>Start SPEC_ONLY assessment</button>
      {job&&<><p role="status">Assessment status: <strong>{job.status}</strong></p>{["QUEUED","PROCESSING"].includes(job.status)&&<button className="secondary" onClick={()=>void cancel()}>Cancel assessment</button>}</>}
      {job?.status==="FAILED"&&<p className="error">Assessment failed: {job.errorCode||"Unexpected error"}</p>}
    </section>}
    {report&&<section><h2>4. Evidence-backed report</h2>
      <p><strong>{report.operationsAssessed}</strong> operations assessed · <strong>{report.observationCount}</strong> observations · 0 confirmed runtime vulnerabilities (not tested)</p>
      <h3>Observations requiring review</h3>{findings.length===0&&<p>No rule observations in this specification. Runtime security remains UNKNOWN.</p>}
      {findings.map(f=><article key={f.id} className="finding"><div><strong>{f.ruleId}</strong> · {f.operationKey||"Document-wide"}</div><p>{f.explanation}</p><p><strong>Evidence:</strong> {f.evidenceId}</p><p><strong>Recommendation:</strong> {f.remediation}</p><small>SPEC_OBSERVATION · SPEC_ONLY · Review required</small></article>)}
      <h3>Coverage and limitations</h3><p>{report.rulesExecuted.length} deterministic rules executed. Runtime validation: {String(report.coverage.runtimeValidation)}</p><ul>{report.limitations.map(s=><li key={s}>{s}</li>)}</ul>
    </section>}
    <footer>Independent API Family · No Main Platform canonical finding promotion · No VERIFIED_FIXED authority</footer>
  </main>;
}
