import React,{useCallback,useEffect,useState} from "react";
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
type Scope={id:string;specification_id:string;fixture_id:string;max_evaluations:number;permit_id?:string};
type Policy={id:string;version:string;ruleIds:string[]};
type Stage={stage_id:string;stage_type:string;ordinal:number;status:string;planned:number;reason:string|null};
type Preview={plan:{stages:{id:string;type:string;dependencies:string[];rules:string[];
 evaluationKeys:string[]}[];rules:{id:string}[];evaluations:{evaluationKey:string;operationKey:string}[];
 binding:{specificationId:string}};authorizationReady:boolean;executable:boolean;denialCode:string|null;
 remainingPermitEvaluations:number;planFingerprint:string};
type Job={id:string;status:string;error_code:string|null;plan:{maxEvaluations:number};
 stages:Stage[];accounting:Record<string,number>};
type Report={status:string;observations:{ruleId:string;remediation:string;fingerprint:string}[];
 coverage:{passed:number;observed:number;unknown:number};
 accounting:{planned:number;executed:number;uncertain:number;notRun:number};limitations:string[]};
type Safety={schemaVersion:string;warning:string;
 execution:{
  queueRecordId:string|null;currentAttemptId:string|null;lifecycle:string;deadline:string|null;
  terminalReason:string|null;provenance:string;
  authorization:{permitId:string;permitExpiresAt:string;status:string;
   consumed:number;reserved:number;rateUsed:number}|null;
  checkpoints:{stage_id:string;status:string;ordinal:number;reason:string|null}[];
  receipts:{state:string;total:number}[];
 };
 queue:{queueState:string;claimGeneration:number;retryCount:number;lockedUntil:string|null;
 nextEligibleAt:string|null;lastErrorCode:string|null}|null;
 attempts:{id:string;claim_generation:number;state:string;started_at:string;last_heartbeat_at:string;
 finished_at:string|null;failure_code:string|null}[];
 events:{kind:string;code:string;occurred_at:string}[];
 quarantine:{reason_code:string;attempts:number}|null};
type History={id:string;status:string;policy_id:string;fingerprint:string;created_at:string};
async function api<T>(token:string,path:string,options?:RequestInit):Promise<T>{
 const r=await fetch(BASE+path,{...options,headers:{"authorization":"Bearer "+token,
  "content-type":"application/json",...options?.headers}});
 const data=await r.json() as T & {error?:string};
 if(!r.ok)throw new Error(data.error??"ORCHESTRATION_REQUEST_FAILED");
 return data;
}
export function PtOrchestrationConsole({token,targetId}:{token:string;targetId:string}){
 const [scopes,setScopes]=useState<Scope[]>([]);
 const [scopeId,setScopeId]=useState("");
 const [policies,setPolicies]=useState<Policy[]>([]);
 const [policyId,setPolicyId]=useState("SYNTHETIC_PT_COMPLETE_SUPPORTED");
 const [profile,setProfile]=useState("SECURE_BASELINE");
 const [preview,setPreview]=useState<Preview|null>(null);
 const [jobId,setJobId]=useState("");
 const [job,setJob]=useState<Job|null>(null);
 const [report,setReport]=useState<Report|null>(null);
 const [safety,setSafety]=useState<Safety|null>(null);
 const [terminal,setTerminal]=useState<{code:string;accounting:Record<string,number>}|null>(null);
 const [findings,setFindings]=useState<{rule_id:string;status:string;fingerprint:string}[]>([]);
 const [coverage,setCoverage]=useState<{rule_id:string;status:string;code:string}[]>([]);
 const [history,setHistory]=useState<History[]>([]);
 const [comparison,setComparison]=useState<unknown>(null);
 const [compareId,setCompareId]=useState("");
 const [stop,setStop]=useState(false);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const [submitKey,setSubmitKey]=useState(()=>crypto.randomUUID());
 const refreshCatalog=useCallback(async()=>{
  const [s,p,h,currentStop]=await Promise.all([
   api<Scope[]>(token,"/v6/pt/targets/"+targetId+"/scopes?limit=50"),
   api<{profiles:Policy[]}>(token,"/v9/pt/policies"),
   api<History[]>(token,"/v9/pt/targets/"+targetId+"/history?limit=30"),
   api<{enabled:boolean}>(token,"/v6/pt/stop")
  ]);
  setScopes(s.filter(x=>x.fixture_id==="pt-security-v1"));
  setPolicies(p.profiles);setHistory(h);setStop(currentStop.enabled);
 },[token,targetId]);
 useEffect(()=>{let active=true;void refreshCatalog().catch(e=>{if(active)setError(String(e));});
  return()=>{active=false;};},[refreshCatalog]);
 useEffect(()=>{setScopeId(scopes[0]?.id??"");},[scopes]);
 useEffect(()=>{
  let active=true;setPreview(null);
  if(!scopeId)return;
  const q=new URLSearchParams({policyId,profile});
  void api<Preview>(token,"/v9/pt/scopes/"+scopeId+"/preview?"+q).then(p=>{if(active)setPreview(p);})
   .catch(e=>{if(active)setError(e instanceof Error?e.message:"PREVIEW_FAILED");});
  return()=>{active=false;};
 },[token,scopeId,policyId,profile]);
 const refreshJob=useCallback(async()=>{
  if(!jobId)return;
  const [current,diagnostics]=await Promise.all([
   api<Job>(token,"/v9/pt/orchestrations/"+jobId),
   api<Safety>(token,"/v10/workers/assessments/"+jobId+"/execution")
  ]);
  setJob(current);setSafety(diagnostics);
  if(current.status==="COMPLETED"){
   const [r,f,c]=await Promise.all([
    api<Report>(token,"/v9/pt/orchestrations/"+jobId+"/report"),
    api<typeof findings>(token,"/v7/pt/jobs/"+jobId+"/findings"),
    api<typeof coverage>(token,"/v7/pt/jobs/"+jobId+"/coverage")
   ]);
   setReport(r);setFindings(f);setCoverage(c);setTerminal(null);
  }else if(["FAILED","CANCELLED"].includes(current.status)){
   const t=await api<{code:string;accounting:Record<string,number>}>(token,
    "/v9/pt/orchestrations/"+jobId+"/terminal");
   setTerminal(t);setReport(null);
  }
 },[token,jobId]);
 useEffect(()=>{
  if(!jobId)return;
  void refreshJob().catch(e=>setError(String(e)));
  if(job?.status&& !["QUEUED","PROCESSING"].includes(job.status))return;
  const interval=setInterval(()=>{void refreshJob().catch(e=>setError(String(e)));},1500);
  return()=>clearInterval(interval);
 },[jobId,job?.status,refreshJob]);
 async function action(f:()=>Promise<void>){
  setBusy(true);setError("");
  try{await f();}catch(e){setError(e instanceof Error?e.message:"ORCHESTRATION_ACTION_FAILED");}
  finally{setBusy(false);}
 }
 async function start(){
  if(!scopeId||!preview?.executable)return;
  await action(async()=>{
   const r=await api<{id:string}>(token,"/v9/pt/scopes/"+scopeId+"/orchestrations",{
    method:"POST",headers:{"idempotency-key":submitKey},body:JSON.stringify({policyId,profile})
   });
   setJobId(r.id);setReport(null);setTerminal(null);setCoverage([]);setFindings([]);
   setSubmitKey(crypto.randomUUID());await refreshCatalog();
  });
 }
 async function cancel(){
  if(!jobId)return;
  await action(async()=>{
   await api(token,"/v9/pt/orchestrations/"+jobId+"/cancel",{method:"POST"});
   await refreshJob();
  });
 }
 async function exportJson(){
  if(!jobId)return;
  await action(async()=>{
   const r=await fetch(BASE+"/v9/pt/orchestrations/"+jobId+"/export",{
    headers:{authorization:"Bearer "+token}});
   if(!r.ok)throw new Error("JSON_EXPORT_FAILED");
   const blob=await r.blob();const url=URL.createObjectURL(blob);
   const a=document.createElement("a");a.href=url;a.download="synthetic-orchestration-"+jobId+".json";
   document.body.append(a);a.click();a.remove();URL.revokeObjectURL(url);
  });
 }
 return <section aria-label="Autonomous API security orchestration">
  <h2>API Penetration Testing → Autonomous Orchestration</h2>
  <p><strong>ISOLATED SYNTHETIC AUTONOMOUS API PT</strong></p>
  <p><strong>NOT AUTHORIZED FOR LIVE CUSTOMER API TESTING</strong></p>
  <p><strong>REAL HOST AUTHORIZATION UNAVAILABLE</strong></p>
  <p><strong>ISOLATED SYNTHETIC API SECURITY EXECUTION</strong></p>
  <p><strong>REAL CUSTOMER API TESTING NOT AUTHORIZED</strong></p>
  <p><strong>WORKER RECOVERY DOES NOT GRANT NEW SECURITY AUTHORITY</strong></p>
  <p>This version only evaluates isolated repository-owned fixtures. Authorization is issued separately by the trusted test authority.</p>
  {error&&<p role="alert" className="error">{error}</p>}
  <p role="status">Emergency stop: {stop?"ACTIVE — admission blocked":"Not active"}</p>
  <label>Approved synthetic scope
   <select value={scopeId} onChange={e=>setScopeId(e.target.value)}>
    <option value="">Select approved scope</option>{scopes.map(s=><option value={s.id} key={s.id}>
     {s.id.slice(0,8)} · spec {s.specification_id.slice(0,8)} · budget {s.max_evaluations}
    </option>)}
   </select>
  </label>
  <label>Trusted policy profile
   <select value={policyId} onChange={e=>setPolicyId(e.target.value)}>
    {policies.map(p=><option key={p.id} value={p.id}>{p.id} · v{p.version}</option>)}
   </select>
  </label>
  <label>Trusted fixture profile
   <select value={profile} onChange={e=>setProfile(e.target.value)}>
    {["SECURE_BASELINE","MISSING_AUTH_ENFORCEMENT","CROSS_USER_ACCESS_WEAKNESS",
      "ROLE_RESTRICTION_WEAKNESS","SENSITIVE_RESPONSE_EXPOSURE","INSECURE_CACHE_POLICY"]
      .map(p=><option key={p} value={p}>{p}</option>)}
   </select>
  </label>
  {!scopeId&&<p>No eligible trusted security fixture scope yet. Propose, approve and issue a separate synthetic permit using the existing PT console.</p>}
  {preview&&<article>
   <h3>Immutable execution plan preview</h3>
   <p>Specification: {preview.plan.binding.specificationId}</p>
   <p>Fingerprint: <code>{preview.planFingerprint}</code></p>
   <p>Planned evaluations: {preview.plan.evaluations.length} · Remaining permit budget: {preview.remainingPermitEvaluations}</p>
   <p>Authorization readiness: {preview.authorizationReady?"VALID":preview.denialCode??"UNKNOWN"} · Executable: {String(preview.executable)}</p>
   <h4>Automatically selected stages / dependencies</h4>
   <ol>{preview.plan.stages.map(s=><li key={s.id}>
    <strong>{s.type}</strong> · depends on {s.dependencies.join(", ")||"none"} · {s.evaluationKeys.length} evaluations
    {s.rules.length>0&&<p>Rules: {s.rules.join(", ")}</p>}
   </li>)}</ol>
   <h4>Governed operation keys</h4><p>{[...new Set(preview.plan.evaluations.map(e=>e.operationKey))].join(", ")}</p>
   <button onClick={()=>void start()} disabled={busy||!preview.executable||stop}>Start authorized orchestration</button>
  </article>}
  {job&&<article>
   <h3>Persisted orchestration progress</h3>
   <p role="status">Job {jobId} · {job.status} {job.error_code??""}</p>
   <p>Governed interactions: {job.accounting.CONSUMED??0} consumed · {job.accounting.UNCERTAIN??0} uncertain · {job.accounting.RESERVED??0} reserved</p>
   <ol>{job.stages.map(s=><li key={s.stage_id}><strong>{s.stage_type}</strong> — {s.status} · budget {s.planned} {s.reason??""}</li>)}</ol>
   {["QUEUED","PROCESSING"].includes(job.status)&&<button disabled={busy} onClick={()=>void cancel()}>Cancel orchestration</button>}
  </article>}
  {safety&&job&&<article aria-label="Worker execution safety diagnostics">
   <h3>Worker safety, recovery and attempt history</h3>
   <p role="status">Queue: {safety.queue?.queueState??"NO ACTIVE QUEUE RECORD"} · generation {safety.queue?.claimGeneration??"none"} · retries {safety.queue?.retryCount??0}</p>
   {safety.queue?.lockedUntil&&<p>Current lease expires: {safety.queue.lockedUntil}</p>}
   {safety.queue?.nextEligibleAt&&<p>Next eligible retry: {safety.queue.nextEligibleAt}</p>}
   {safety.queue?.lastErrorCode&&<p>Last infrastructure failure: {safety.queue.lastErrorCode}</p>}
   {safety.quarantine&&<p role="alert">Terminal quarantine: {safety.quarantine.reason_code} · attempts {safety.quarantine.attempts}. No automatic replay.</p>}
   <h4>Governed execution and recovery</h4>
   <p>Lifecycle: {safety.execution.lifecycle} · current attempt: {safety.execution.currentAttemptId??"none"}</p>
   {safety.execution.deadline&&<p>Approved job deadline: {safety.execution.deadline}</p>}
   {safety.execution.authorization&&<p>Permit status: {safety.execution.authorization.status} · permit expires: {safety.execution.authorization.permitExpiresAt} · consumed {safety.execution.authorization.consumed} · reserved {safety.execution.authorization.reserved} · rate used {safety.execution.authorization.rateUsed}</p>}
   {safety.execution.receipts.length>0&&<p>Governed receipts: {safety.execution.receipts.map(r=>r.state+" "+r.total).join(" · ")}</p>}
   {safety.execution.terminalReason&&<p role="alert">Terminal reason: {safety.execution.terminalReason}</p>}
   <h4>Persisted worker attempts</h4>
   {safety.attempts.length===0?<p>Not claimed by a worker yet.</p>:<ol>{safety.attempts.map(a=>
    <li key={a.id}>Generation {a.claim_generation} · {a.state} · started {a.started_at}
     {a.failure_code?" · "+a.failure_code:""}</li>)}</ol>}
   <h4>Auditable execution events</h4>
   {safety.events.length===0?<p>No worker events recorded.</p>:<ul>{safety.events.map((e,i)=>
    <li key={e.occurred_at+"-"+i}>{e.kind} · {e.code}</li>)}</ul>}
   <button className="secondary" disabled={busy} onClick={()=>void action(refreshJob)}>Refresh actual worker state</button>
   <p>{safety.warning}</p>
  </article>}
  {report&&<article>
   <h3>Immutable completed synthetic report</h3>
   <p>Coverage: {report.coverage.passed} PASS · {report.coverage.observed} OBSERVED · {report.coverage.unknown} UNKNOWN</p>
   <p>Budget: {report.accounting.executed}/{report.accounting.planned} · uncertain {report.accounting.uncertain} · not run {report.accounting.notRun}</p>
   <h4>Evidence-backed synthetic observations</h4>
   {report.observations.length===0?<p>No synthetic fixture observations. Not a real customer security certification.</p>:
    report.observations.map(x=><p key={x.ruleId}><strong>{x.ruleId}</strong> · {x.remediation}</p>)}
   <h4>Rule outcomes</h4>{coverage.map(x=><p key={x.rule_id}>{x.rule_id}: {x.status} — {x.code}</p>)}
   <p>{findings.length} evidence-backed synthetic observations available for review.</p>
   <ul>{report.limitations.map(x=><li key={x}>{x}</li>)}</ul>
   <button onClick={()=>void exportJson()} disabled={busy}>Export immutable JSON</button>
  </article>}
  {terminal&&<article><h3>Terminal diagnostic — not a successful PT report</h3>
   <p>{terminal.code}</p><p>Accounting: {JSON.stringify(terminal.accounting)}</p>
   <p>Missing evidence does not imply safety.</p>
  </article>}
  <h3>Orchestration history and compatible comparison</h3>
  <button onClick={()=>void action(refreshCatalog)} disabled={busy}>Refresh history</button>
  <label>Historical run
   <select value={jobId} onChange={e=>{setJobId(e.target.value);setJob(null);setSafety(null);setReport(null);setTerminal(null);}}>
    <option value="">Choose saved run</option>{history.map(h=><option key={h.id} value={h.id}>{h.id.slice(0,8)} · {h.status} · {h.policy_id}</option>)}
   </select>
  </label>
  <label>Comparison run
   <select value={compareId} onChange={e=>setCompareId(e.target.value)}>
    <option value="">Select second completed run</option>{history.filter(h=>h.status==="COMPLETED"&&h.id!==jobId).map(h=>
     <option key={h.id} value={h.id}>{h.id.slice(0,8)} · {h.policy_id}</option>)}
   </select>
  </label>
  <button disabled={busy||!jobId||!compareId} onClick={()=>void action(async()=>{
   setComparison(await api(token,"/v9/pt/orchestrations/"+jobId+"/compare/"+compareId));
  })}>Compare compatible synthetic runs</button>
  {comparison!==null&&<pre>{JSON.stringify(comparison,null,2)}</pre>}
  <p>UNKNOWN ≠ SAFE · AUTONOMOUS PLAN ≠ AUTHORIZATION · SYNTHETIC OBSERVATION ≠ CONFIRMED CUSTOMER FINDING</p>
 </section>;
}
