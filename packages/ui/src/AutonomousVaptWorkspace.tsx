import React,{useCallback,useEffect,useState} from "react";
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
type Scope={id:string;specification_id:string;fixture_id:string;max_evaluations:number};
type Spec={id:string;filename:string;fingerprint:string};
type Policy={id:string;version:string;ruleIds:string[]};
type Child={id:string;engine_version:string;status:string;error_code:string|null};
type Job={id:string;status:string;error_code:string|null;mode:string;
 plan:{stages:{id:string;engine:string;dependencies:string[]}[];rules:{id:string}[];
  plannedEvaluations:number;operations:{key:string;method:string;path:string}[]};
 children:Child[]};
type Finding={key:string;source:string;ruleId:string;category:string;impact:string;
 operationKey:string|null;explanation:string;remediation:string;correlation:string;
 priority:{rank:number;reason:string};evidenceFingerprint:string};
type Report={status:string;mode:string;fullAuthorizedVaptCompleted:boolean;
 findings:Finding[];relationships:{key:string;relationship:string;limitation:string}[];
 coverage:{importedOperations:number;offlineOperations:number;ptRulesSelected:number;
  ptRulesExecuted:number;ptEvaluationsPlanned:number;ptEvaluationsExecuted:number;ptNotTested:boolean};
 limitations:string[];components:Child[];customerRuntimeVerified:boolean;verifiedFixed:boolean};
type History={id:string;mode:string;status:string;created_at:string};
type Preview={plan:{stages:{id:string;engine:string;dependencies:string[]}[];plannedEvaluations:number;
 rules:{id:string}[];operations:{key:string;method:string;path:string}[]};
 authorizationReady:boolean;executable:boolean;denialCode:string|null;remainingPermitEvaluations:number};
async function api<T>(token:string,path:string,options?:RequestInit):Promise<T>{
 const res=await fetch(BASE+path,{...options,headers:{"authorization":"Bearer "+token,
  "content-type":"application/json",...options?.headers}});
 const response=await res.json() as T & {error?:string};
 if(!res.ok)throw new Error(response.error??"VAPT_API_FAILED");
 return response;
}
const failMessage=(e:unknown)=>e instanceof Error?e.message:"UNKNOWN_VAPT_ERROR";
export function AutonomousVaptWorkspace({token,targetId}:{token:string;targetId:string}){
 const [specs,setSpecs]=useState<Spec[]>([]);
 const [specId,setSpecId]=useState("");
 const [scopes,setScopes]=useState<Scope[]>([]);
 const [scopeId,setScopeId]=useState("");
 const [policies,setPolicies]=useState<Policy[]>([]);
 const [policyId,setPolicyId]=useState("SYNTHETIC_PT_COMPLETE_SUPPORTED");
 const [profile,setProfile]=useState("SECURE_BASELINE");
 const [mode,setMode]=useState<"OFFLINE_ONLY"|"GOVERNED_SYNTHETIC">("GOVERNED_SYNTHETIC");
 const [preview,setPreview]=useState<Preview|null>(null);
 const [jobId,setJobId]=useState("");
 const [job,setJob]=useState<Job|null>(null);
 const [report,setReport]=useState<Report|null>(null);
 const [terminal,setTerminal]=useState<{status:string;code:string}|null>(null);
 const [findings,setFindings]=useState<Finding[]>([]);
 const [history,setHistory]=useState<History[]>([]);
 const [compareId,setCompareId]=useState("");
 const [comparison,setComparison]=useState<unknown>(null);
 const [submitKey,setSubmitKey]=useState(()=>crypto.randomUUID());
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const refresh=useCallback(async()=>{
  const [s,p,h,sp]=await Promise.all([
   api<Scope[]>(token,"/v6/pt/targets/"+targetId+"/scopes?limit=50"),
   api<{profiles:Policy[]}>(token,"/v9/pt/policies"),
   api<History[]>(token,"/v11/api-vapt/targets/"+targetId+"/history?limit=30"),
   api<Spec[]>(token,"/v1/targets/"+targetId+"/specifications?limit=50")
  ]);
  setScopes(s.filter(x=>x.fixture_id==="pt-security-v1"));
  setPolicies(p.profiles);setHistory(h);setSpecs(sp);
 },[token,targetId]);
 useEffect(()=>{let active=true;
  setScopes([]);setSpecs([]);setScopeId("");setSpecId("");setJobId("");setJob(null);
  setReport(null);setTerminal(null);setFindings([]);setError("");
  void refresh().catch(e=>{if(active)setError(failMessage(e));});
  return ()=>{active=false;};},[refresh]);
 useEffect(()=>{setScopeId(scopes[0]?.id??"");},[scopes]);
 useEffect(()=>{setSpecId(specs[0]?.id??"");},[specs]);
 useEffect(()=>{
  let active=true;setPreview(null);
  if(mode!=="GOVERNED_SYNTHETIC"||!scopeId)return;
  const query=new URLSearchParams({policyId,profile});
  void api<Preview>(token,"/v11/api-vapt/scopes/"+scopeId+"/preview?"+query)
   .then(x=>{if(active)setPreview(x);})
   .catch(e=>{if(active)setError(failMessage(e));});
  return()=>{active=false;};
 },[token,mode,scopeId,policyId,profile]);
 const refreshAssessment=useCallback(async()=>{
  if(!jobId)return;
  const current=await api<Job>(token,"/v11/api-vapt/assessments/"+jobId);
  setJob(current);
  if(current.status==="COMPLETED"){
   const [r,f]=await Promise.all([
    api<Report>(token,"/v11/api-vapt/assessments/"+jobId+"/report"),
    api<{projection:Finding}[]>(token,"/v11/api-vapt/assessments/"+jobId+"/findings?limit=50")
   ]);
   setReport(r);setFindings(f.filter(x=>x.projection.source).map(x=>x.projection));
   setTerminal(null);
  }else if(["FAILED","CANCELLED"].includes(current.status)){
   const t=await api<{status:string;code:string}>(token,"/v11/api-vapt/assessments/"+jobId+"/terminal");
   setTerminal(t);setReport(null);
  }
 },[token,jobId]);
 useEffect(()=>{if(!jobId)return;let live=true;
  const check=()=>{if(live)void refreshAssessment().catch(e=>{if(live)setError(failMessage(e));});};
  check();const timer=setInterval(check,1500);return()=>{live=false;clearInterval(timer);};
 },[jobId,refreshAssessment]);
 async function execute(task:()=>Promise<void>){
  setBusy(true);setError("");
  try{await task();}catch(e){setError(failMessage(e));}
  finally{setBusy(false);}
 }
 async function start(){
  await execute(async()=>{
   const request=mode==="OFFLINE_ONLY"?
    {mode,targetId,specificationId:specId}:{mode,scopeId,policyId,profile};
   const result=await api<{id:string}>(token,"/v11/api-vapt/assessments",{
    method:"POST",headers:{"idempotency-key":submitKey},body:JSON.stringify(request)});
   setJobId(result.id);setReport(null);setTerminal(null);setComparison(null);
   setSubmitKey(crypto.randomUUID());await refresh();
  });
 }
 async function cancel(){if(!jobId)return;
  await execute(async()=>{await api(token,"/v11/api-vapt/assessments/"+jobId+"/cancel",{method:"POST",body:"{}"});await refreshAssessment();});
 }
 async function reassess(){if(!jobId)return;
  await execute(async()=>{
   const result=await api<{id:string}>(token,"/v11/api-vapt/assessments/"+jobId+"/reassess",{
    method:"POST",headers:{"idempotency-key":submitKey},body:"{}"});
   setSubmitKey(crypto.randomUUID());setJobId(result.id);setJob(null);setReport(null);setComparison(null);
   await refresh();
  });
 }
 async function compare(){if(!jobId||!compareId)return;
  await execute(async()=>{
   setComparison(await api<unknown>(token,"/v11/api-vapt/assessments/"+jobId+"/compare/"+compareId));
  });
 }
 async function exportJSON(){if(!jobId)return;
  await execute(async()=>{
   const r=await fetch(BASE+"/v11/api-vapt/assessments/"+jobId+"/export",{
    headers:{"authorization":"Bearer "+token}});
   if(!r.ok)throw new Error((await r.json() as {error?:string}).error??"EXPORT_FAILED");
   const url=URL.createObjectURL(await r.blob());
   const anchor=document.createElement("a");anchor.href=url;anchor.download="isolated-api-vapt-"+jobId+".json";
   document.body.append(anchor);anchor.click();anchor.remove();URL.revokeObjectURL(url);
  });
 }
 const ready=mode==="OFFLINE_ONLY"?Boolean(specId):Boolean(preview?.executable);
 return <section role="region" aria-label="Autonomous API VAPT workspace">
  <h2>Autonomous API VAPT</h2>
  <p><strong>ISOLATED SYNTHETIC AUTONOMOUS API VAPT</strong></p>
  <p>NOT AUTHORIZED FOR LIVE CUSTOMER API TESTING</p>
  <p>NO CUSTOMER VULNERABILITY IS CONFIRMED BY SYNTHETIC FIXTURES</p>
  <p>REAL HOST AUTHORIZATION UNAVAILABLE</p>
  {error&&<p role="alert" className="error">{error}</p>}
  <div className="formgrid">
   <label>Assessment mode<select value={mode} onChange={e=>setMode(e.target.value as "OFFLINE_ONLY"|"GOVERNED_SYNTHETIC")}>
    <option value="GOVERNED_SYNTHETIC">Governed synthetic VAPT</option>
    <option value="OFFLINE_ONLY">Specification analysis only (no PT)</option>
   </select></label>
   {mode==="OFFLINE_ONLY"?
    <label>Immutable specification<select value={specId} onChange={e=>setSpecId(e.target.value)}>
     <option value="">Select specification</option>
     {specs.map(x=><option key={x.id} value={x.id}>{x.filename} · {x.fingerprint.slice(0,10)}</option>)}
    </select></label>:
    <>
     <label>Authorized synthetic scope<select value={scopeId} onChange={e=>setScopeId(e.target.value)}>
      <option value="">Select scope</option>
      {scopes.map(x=><option key={x.id} value={x.id}>{x.id.slice(0,12)} · {x.max_evaluations} evaluations</option>)}
     </select></label>
     <label>Deterministic policy<select value={policyId} onChange={e=>setPolicyId(e.target.value)}>
      {policies.map(x=><option key={x.id} value={x.id}>{x.id} · {x.version}</option>)}
     </select></label>
     <label>Trusted fixture profile<select value={profile} onChange={e=>setProfile(e.target.value)}>
      {["SECURE_BASELINE","MISSING_AUTH_ENFORCEMENT","CROSS_USER_ACCESS_WEAKNESS","ROLE_RESTRICTION_WEAKNESS","SENSITIVE_RESPONSE_EXPOSURE","INSECURE_CACHE_POLICY"].map(x=><option key={x}>{x}</option>)}
     </select></label>
    </>}
  </div>
  <h3>Immutable plan and authorization preview</h3>
  {mode==="OFFLINE_ONLY"?<p>SPEC_ONLY — zero runtime evaluations, no PT permit, full governed VAPT NOT completed.</p>:
   preview?<div>
    <p>Permit readiness: <strong>{preview.authorizationReady?"VALID":"BLOCKED"}</strong> · {preview.denialCode??"No admission blocker"}</p>
    <p>Planned evaluations: {preview.plan.plannedEvaluations} · Remaining authorized: {preview.remainingPermitEvaluations}</p>
    <p>Applicable synthetic rules: {preview.plan.rules.map(x=>x.id).join(", ")}</p>
    <ul>{preview.plan.stages.map(s=><li key={s.id}>{s.id} — {s.engine} (after {s.dependencies.join(", ")||"start"})</li>)}</ul>
   </div>:<p>Choose an existing signed-permit scope to see actual eligibility.</p>}
  <p>Authorization must be issued separately by the existing Phase 06 test-only permit authority.</p>
  <button disabled={busy||!ready||!token} onClick={()=>void start()}>Start one autonomous assessment</button>
  <h3>Persisted execution progress</h3>
  {!job&&<p>No combined assessment selected.</p>}
  {job&&<div>
   <p role="status">Parent: <strong>{job.status}</strong> · {job.id}</p>
   {job.error_code&&<p role="alert">Failure: {job.error_code}</p>}
   <ul>{job.children.map(x=><li key={x.id}>{x.engine_version}: {x.status}{x.error_code?" · "+x.error_code:""}</li>)}</ul>
   {["QUEUED","PROCESSING"].includes(job.status)&&<button disabled={busy} onClick={()=>void cancel()}>Cancel assessment</button>}
  </div>}
  {terminal&&<div><h3>Terminal diagnostics (not successful VAPT)</h3><p>{terminal.status}: {terminal.code}</p></div>}
  {report&&<div>
   <h3>Immutable composite security report</h3>
   <p>{report.fullAuthorizedVaptCompleted?"Governed synthetic components completed":"OFFLINE_ONLY — runtime testing NOT performed"}</p>
   <p>Imported operations {report.coverage.importedOperations} · offline analyzed {report.coverage.offlineOperations}</p>
   <p>PT rules {report.coverage.ptRulesExecuted}/{report.coverage.ptRulesSelected}, evaluations {report.coverage.ptEvaluationsExecuted}/{report.coverage.ptEvaluationsPlanned}</p>
   <h4>Evidence-backed unified findings</h4>
   {findings.length===0?<p>No observed conditions. Unknown coverage remains unknown.</p>:
    findings.map(x=><article className="finding" key={x.key}>
     <strong>{x.ruleId}</strong> · {x.source} · {x.operationKey??"Document-wide"}
     <p>{x.explanation}</p>
     <p>Impact {x.impact} · Correlation {x.correlation} · Triage {x.priority.reason}</p>
     <p>Evidence fingerprint <code>{x.evidenceFingerprint}</code></p>
     <p>Remediation: {x.remediation}</p>
    </article>)}
   <h4>Coverage and limitations</h4><ul>{report.limitations.map(x=><li key={x}>{x}</li>)}</ul>
   <button onClick={()=>void exportJSON()} disabled={busy}>Export actual immutable JSON report</button>
   <button onClick={()=>void reassess()} disabled={busy}>Reassess with fresh authorization</button>
  </div>}
  <h3>Combined assessment history</h3>
  <button disabled={busy} onClick={()=>void execute(refresh)}>Refresh history</button>
  {history.length===0&&<p>No persisted Phase 11 assessments for this target.</p>}
  <ul>{history.map(x=><li key={x.id}>
   <button className="secondary" onClick={()=>{setJobId(x.id);setComparison(null);}}>
    {x.mode} · {x.status} · {new Date(x.created_at).toLocaleString()}
   </button>
  </li>)}</ul>
  {jobId&&<div>
   <label>Compare with previous completed assessment<select value={compareId} onChange={e=>setCompareId(e.target.value)}>
    <option value="">Select historical assessment</option>
    {history.filter(x=>x.id!==jobId&&x.status==="COMPLETED").map(x=><option key={x.id} value={x.id}>{x.id.slice(0,12)} · {x.mode}</option>)}
   </select></label>
   <button disabled={busy||!compareId} onClick={()=>void compare()}>Compare compatible evidence</button>
   {comparison!==null&&<pre>{JSON.stringify(comparison,null,2)}</pre>}
  </div>}
 </section>;
}
