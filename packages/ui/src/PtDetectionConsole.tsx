import React,{useCallback,useEffect,useMemo,useState} from "react";
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
type Spec={specificationId:string;version:number;format:string};
type Op={key:string;method:string;path:string};
type Rule={id:string;revision:string;category:string;path:string;evaluations:number;
 requiredIdentities:string[];impact:string;description:string;remediation:string};
type ScopeDetail={scope:{id:string;operation_keys:string[];max_evaluations:number};
 requested:boolean;permit:{id:string;revoked:boolean;expired:boolean;expiresAt:string;consumed:number;reserved:number}|null};
type Status={id:string;status:string;errorCode:string|null;counts:Record<string,number>;plan_fingerprint:string};
type Progress={status:string;plannedEvaluations:number;executedEvaluations:number;uncertainEvaluations:number;inFlightReservations:number;notYetExecuted:number;complete:boolean};
type Preview={executable:boolean;plannedEvaluations:number;applicableEvaluations:number;rules:{ruleId:string;applicable:boolean;reason:string;operationKey:string|null}[]};
type Observation={ruleId:string;category:string;impact:string;confidence:string;status:string;code:string;fingerprint:string;
 remediation:string;evidence:{actor:string;path:string;status:number;exposedPaths:string[];cacheControl:string|null}[]};
type Terminal={schemaVersion:string;status:string;errorCode:string;notice:string;rules:{rule_id:string;status:string;code:string;planned:number;executed:number;uncertain:number;notRun:number}[];
 totals:{plannedEvaluations:number;executedEvaluations:number;uncertainEvaluations:number;notRunEvaluations:number};
 assessmentComplete:false;verifiedFixed:false;customerRuntimeVerified:false;limitations:string[]};
type Report={schemaVersion:string;status:string;coverage:{requested:number;executed:number;passed:number;observed:number;skipped:number;inconclusive:number;actualEvaluations:number};
 observations:Observation[];limitations:string[];customerNetworkRequests:number;verifiedFixed:boolean;syntheticOnly:boolean};
async function call<T>(token:string,path:string,method="GET",body?:unknown,key?:string):Promise<T>{
 const response=await fetch(BASE+path,{method,headers:{"authorization":"Bearer "+token,
  ...(body===undefined?{}:{"content-type":"application/json"}),...(key?{"idempotency-key":key}:{})},
  ...(body===undefined?{}:{body:JSON.stringify(body)})});
 const payload=await response.json() as T&{error?:string};
 if(!response.ok)throw new Error(payload.error??"DETECTION_REQUEST_FAILED");
 return payload;
}
export function PtDetectionConsole({token,targetId,active}:{token:string;targetId:string;active:boolean}){
 const [specs,setSpecs]=useState<Spec[]>([]),[specId,setSpecId]=useState("");
 const [operations,setOperations]=useState<Op[]>([]),[rules,setRules]=useState<Rule[]>([]);
 const [profiles,setProfiles]=useState<string[]>([]),[profile,setProfile]=useState("SECURE_BASELINE");
 const [chosen,setChosen]=useState<string[]>([]),[scopeId,setScopeId]=useState("");
 const [scope,setScope]=useState<ScopeDetail|null>(null),[jobId,setJobId]=useState("");
 const [job,setJob]=useState<Status|null>(null),[report,setReport]=useState<Report|null>(null);
 const [progress,setProgress]=useState<Progress|null>(null),[preview,setPreview]=useState<Preview|null>(null);
 const [terminal,setTerminal]=useState<Terminal|null>(null);
 const [coverage,setCoverage]=useState<{rule_id:string;status:string;code:string}[]>([]);
 const [history,setHistory]=useState<{id:string;status:string;plan_fingerprint:string}[]>([]);
 const [compareId,setCompareId]=useState(""),[comparison,setComparison]=useState<unknown>(null);
 const [error,setError]=useState(""),[busy,setBusy]=useState(false);
 const work=async(task:()=>Promise<void>)=>{setBusy(true);setError("");try{await task();}
  catch(e){setError(e instanceof Error?e.message:"DETECTION_FAILED");}finally{setBusy(false);}};
 const refresh=useCallback(async()=>{
  if(!targetId||!token)return;
  const [versions,registry,fixtures,previous]=await Promise.all([
   call<Spec[]>(token,"/v2/targets/"+targetId+"/specifications?limit=100"),
   call<{rules:Rule[]}>(token,"/v7/pt/rules"),
   call<{profiles:string[]}>(token,"/v7/pt/fixtures"),
   call<{id:string;status:string;plan_fingerprint:string}[]>(token,"/v7/pt/targets/"+targetId+"/history")]);
  setSpecs(versions);setRules(registry.rules);setProfiles(fixtures.profiles);setHistory(previous);
 },[targetId,token]);
 useEffect(()=>{setSpecs([]);setSpecId("");setScopeId("");setScope(null);setJobId("");setJob(null);
  setReport(null);setTerminal(null);setProgress(null);setPreview(null);setHistory([]);setChosen([]);
  if(active&&targetId)void refresh().catch(e=>setError(String(e)));
 },[active,targetId,refresh]);
 useEffect(()=>{let live=true;setOperations([]);setChosen([]);
  if(specId)void call<Op[]>(token,"/v2/specifications/"+specId+"/operations?limit=100")
   .then(x=>{if(live)setOperations(x);}).catch(e=>{if(live)setError(String(e));});
  return()=>{live=false;};
 },[specId,token]);
 const applicable=useMemo(()=>rules.filter(r=>operations.some(x=>x.method==="GET"&&x.path===r.path)),[rules,operations]);
 const selected=useMemo(()=>rules.filter(x=>chosen.includes(x.id)),[rules,chosen]);
 const total=selected.reduce((count,r)=>count+r.evaluations,0);
 const selectedKeys=[...new Set(operations.filter(x=>selected.some(r=>r.path===x.path&&x.method==="GET")).map(x=>x.key))];
 const refreshScope=useCallback(async()=>{if(scopeId)setScope(await call<ScopeDetail>(token,"/v6/pt/scopes/"+scopeId));},[scopeId,token]);
 const refreshJob=useCallback(async()=>{
  if(!jobId)return;
  const [x,p]=await Promise.all([call<Status>(token,"/v7/pt/jobs/"+jobId),
   call<Progress>(token,"/v8/pt/jobs/"+jobId+"/progress")]);
  setJob(x);setProgress(p);
  if(x.status==="COMPLETED"){
   setTerminal(null);
   try{setReport(await call<Report>(token,"/v7/pt/jobs/"+jobId+"/report"));
    setCoverage(await call<{rule_id:string;status:string;code:string}[]>(token,"/v7/pt/jobs/"+jobId+"/coverage"));}
   catch{setReport(null);setCoverage([]);}
  }else if(x.status==="FAILED"||x.status==="CANCELLED"){
   setReport(null);setCoverage([]);
   setTerminal(await call<Terminal>(token,"/v8/pt/jobs/"+jobId+"/terminal-coverage"));
  }else{setTerminal(null);}

 },[jobId,token]);
 useEffect(()=>{if(!jobId)return;void refreshJob().catch(e=>setError(String(e)));
  if(["COMPLETED","FAILED","CANCELLED"].includes(job?.status??""))return;
  const timer=setInterval(()=>void refreshJob().catch(e=>setError(String(e))),1500);
  return()=>clearInterval(timer);
 },[jobId,job?.status,refreshJob]);
 const propose=()=>work(async()=>{
  if(!specId||!selectedKeys.length||!total)throw new Error("SELECT_APPLICABLE_RULES");
  const x=await call<{id:string}>(token,"/v6/pt/targets/"+targetId+"/scopes","POST",{
   specificationId:specId,operationKeys:selectedKeys,exclusions:[],
   maxEvaluations:total,maxConcurrency:1,ratePerMinute:Math.min(20,total),deadlineMs:30000,
   validityMinutes:15,fixtureId:"pt-security-v1"
  },"pt7-scope-"+crypto.randomUUID());
  setScopeId(x.id);setScope(null);setJobId("");setReport(null);
 });
 const start=()=>work(async()=>{
  const x=await call<{id:string}>(token,"/v7/pt/scopes/"+scopeId+"/detections","POST",
   {profile,ruleIds:chosen},"pt7-job-"+crypto.randomUUID());
  setJobId(x.id);setJob(null);setReport(null);setCoverage([]);
 });
 const exportReport=()=>work(async()=>{
  if(!report)throw new Error("NO_REPORT");
  const data=JSON.stringify(report,null,2),objectUrl=URL.createObjectURL(new Blob([data],{type:"application/json"}));
  const element=document.createElement("a");element.href=objectUrl;element.download="synthetic-pt-"+jobId+".json";
  document.body.appendChild(element);element.click();element.remove();URL.revokeObjectURL(objectUrl);
 });
 return <section aria-label="API PT deterministic detection assessment" role="region">
  <h2>Deterministic API PT Detection Assessment</h2>
  <p><strong>ISOLATED SYNTHETIC API PENETRATION TESTING — NOT CUSTOMER PRODUCTION VULNERABILITY VERIFICATION.</strong></p>
  <p>Versioned engine pt-detection-v1 · Trusted fixture pt-security-v1 · GET-only detection requests · Real Host authorization BLOCKED.</p>
  {error&&<p role="alert" className="error">{error}</p>}
  <button className="secondary" type="button" disabled={busy} onClick={()=>void work(refresh)}>Refresh detection catalog &amp; history</button>
  <label>Imported specification
   <select aria-label="PT detection specification" value={specId} onChange={e=>setSpecId(e.target.value)}>
    <option value="">Choose specification</option>{specs.map(s=><option key={s.specificationId} value={s.specificationId}>v{s.version} {s.format} {s.specificationId.slice(0,8)}</option>)}
   </select>
  </label>
  <label>Trusted synthetic fixture profile
   <select aria-label="PT detection fixture profile" value={profile} onChange={e=>setProfile(e.target.value)}>
    {profiles.map(x=><option key={x} value={x}>{x}</option>)}
   </select>
  </label>
  <fieldset><legend>Versioned security rules and trusted identities</legend>
   {applicable.map(r=><label key={r.id}><input type="checkbox" checked={chosen.includes(r.id)}
    onChange={e=>setChosen(v=>e.target.checked?[...v,r.id]:v.filter(x=>x!==r.id))}/>
    {r.id} · {r.category} · {r.evaluations} evaluations · {r.path} · {r.requiredIdentities.join(" vs ")}
   </label>)}
   {specId&&applicable.length===0&&<p>No applicable trusted GET operation in this imported specification.</p>}
  </fieldset>
  <p>Signed-permit evaluation budget preview: <strong>{total}</strong> · Applicable rules {applicable.length} · Selected {selected.length} · Real customer requests: 0.</p>
  <button type="button" className="secondary" disabled={busy||!specId||!selected.length}
   onClick={()=>void work(async()=>setPreview(await call<Preview>(token,"/v8/pt/specifications/"+specId+"/plan-preview",
    "POST",{profile,ruleIds:chosen,exclusions:[]})))}>Preview governed rule applicability</button>
  {preview&&<section aria-label="Authoritative evaluation plan preview">
   <p>Server-side planned evaluations {preview.plannedEvaluations}, applicable {preview.applicableEvaluations}. All selected rules executable: {String(preview.executable)}.</p>
   <ul>{preview.rules.map(x=><li key={x.ruleId}>{x.ruleId} — {x.applicable?"APPLICABLE":x.reason} · {x.operationKey??"No governed operation"}</li>)}</ul>
  </section>}
  <button disabled={busy||!active||!selected.length||total>20||!specId} onClick={propose}>Propose detection scope</button>
  {scopeId&&<article>
   <h3>Synthetic authorization</h3><p>Scope: {scopeId}</p>
   <button type="button" className="secondary" disabled={busy} onClick={()=>void work(refreshScope)}>Refresh detection permit</button>
   <button type="button" disabled={busy} onClick={()=>void work(async()=>{
    await call(token,"/v6/pt/scopes/"+scopeId+"/request-authorization","POST");
    await refreshScope();
   })}>Request separate synthetic test authority</button>
   <p>{scope?.permit?scope.permit.revoked?"REVOKED":scope.permit.expired?"EXPIRED":"TEST-ONLY PERMIT ISSUED":
    "Authorization not issued. The browser cannot sign a permit."}</p>
   <button disabled={busy||!scope?.permit||scope.permit.revoked||scope.permit.expired} onClick={start}>Start governed detection assessment</button>
  </article>}
  {jobId&&<article>
   <h3>Private worker detection</h3><p>Assessment {jobId} · <strong>{job?.status??"Loading"}</strong> · Customer-network requests 0.</p>
   {job?.errorCode&&<p role="alert">{job.errorCode}</p>}
   {progress&&<p role="status">Persisted governed progress: {progress.executedEvaluations}/{progress.plannedEvaluations} evaluations · {progress.inFlightReservations} in flight · {progress.uncertainEvaluations} uncertain · {progress.notYetExecuted} pending.</p>}
   <button type="button" className="secondary" disabled={busy} onClick={()=>void work(refreshJob)}>Refresh detection results</button>
   {job&&["QUEUED","PROCESSING"].includes(job.status)&&<button disabled={busy} onClick={()=>void work(async()=>{
    await call(token,"/v6/pt/jobs/"+jobId+"/cancel","POST");await refreshJob();
   })}>Cancel detection</button>}
   {terminal&&<section aria-label="Incomplete PT diagnostic coverage" role="status"><h4>Incomplete assessment — diagnostic coverage</h4>
    <p>{terminal.notice}</p><p>Planned {terminal.totals.plannedEvaluations} · Executed {terminal.totals.executedEvaluations} · Uncertain {terminal.totals.uncertainEvaluations} · Not run {terminal.totals.notRunEvaluations}</p>
    <p>Terminal state {terminal.status} · Reason {terminal.errorCode} · VERIFIED_FIXED: false</p>
    <ul>{terminal.rules.map(r=><li key={r.rule_id}>{r.rule_id}: {r.status} ({r.code}) — {r.executed}/{r.planned} executed, {r.notRun} not run</li>)}</ul>
    <p>NOT CUSTOMER PRODUCTION VULNERABILITY VERIFICATION. No successful report was published.</p>
   </section>}
   {report&&<><p>Executed {report.coverage.executed} · Passed {report.coverage.passed} · Synthetic observations {report.coverage.observed} · Skipped {report.coverage.skipped} · Inconclusive {report.coverage.inconclusive}</p>
    <h4>Evidence-backed synthetic PT observations</h4>
    {report.observations.length===0&&<p>No synthetic weakness observed; customer runtime remains unverified.</p>}
    {report.observations.map(o=><article key={o.fingerprint} className="finding"><h5>{o.ruleId} · {o.impact} · {o.confidence}</h5>
     <p>{o.code} · Fingerprint <code>{o.fingerprint}</code></p><p>Remediation: {o.remediation}</p>
     <details><summary>Redacted observed evidence</summary>{o.evidence.map((e,i)=><p key={i}>
      {e.actor} · {e.path} · HTTP {e.status} · Fields {e.exposedPaths.join(", ")} · Cache {e.cacheControl??"not present"}</p>)}</details>
    </article>)}
    <h4>Rule coverage</h4><ul>{coverage.map(r=><li key={r.rule_id}>{r.rule_id}: {r.status} ({r.code})</li>)}</ul>
    <h4>Immutable synthetic report</h4><p>VERIFIED_FIXED: {String(report.verifiedFixed)} · Synthetic only: {String(report.syntheticOnly)}</p>
    <ul>{report.limitations.map(x=><li key={x}>{x}</li>)}</ul>
    <button type="button" onClick={exportReport}>Export persisted JSON report</button>
   </>}
  </article>}
  <h3>Detection history &amp; compatible comparisons</h3>
  {history.map(h=><p key={h.id}><button type="button" className="secondary" onClick={()=>{setJobId(h.id);setReport(null);setTerminal(null);setJob(null);}}>
   View {h.id.slice(0,8)} · {h.status}</button></p>)}
  {jobId&&<><label>Compare against another detection job
   <select aria-label="Comparison assessment" value={compareId} onChange={e=>setCompareId(e.target.value)}>
    <option value="">Choose previous run</option>{history.filter(h=>h.id!==jobId).map(h=><option key={h.id} value={h.id}>{h.id.slice(0,8)}</option>)}
   </select></label>
   <button type="button" disabled={!compareId||busy} onClick={()=>void work(async()=>{
    setComparison(await call(token,"/v7/pt/jobs/"+jobId+"/compare/"+compareId));
   })}>Compare compatible runs</button>
   {comparison!==null&&<pre>{JSON.stringify(comparison,null,2)}</pre>}</>}
 </section>;
}
