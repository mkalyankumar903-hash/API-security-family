import React,{useCallback,useEffect,useState} from "react";
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
type Version={specificationId:string;version:number;format:string};
type Op={key:string;method:string;path:string};
type Scope={id:string;status:string};
type Detail={
 scope:{id:string;specification_id:string;operation_keys:string[];max_evaluations:number;exclusions:string[]};
 requested:boolean;permit:{id:string;tokenHash:string;revoked:boolean;expired:boolean;expiresAt:string;consumed:number;reserved:number}|null;
 realHostExecution:string;
};
type Job={id:string;status:string;errorCode:string|null;permit_id:string;consumed:number;reserved:number;
 max_evaluations:number;counts:Record<string,number>;customerNetworkRequests:number};
type Receipt={id:string;operation_key:string;method:string;path:string;decision:string;code:string;outcome:string;http_status:number|null;response_bytes:number|null;budget_consumed:number};
type Report={status:string;counts:{allowed:number;denied:number;skipped:number};customerNetworkRequests:number;syntheticOnly:boolean;limitations:string[];verifiedFixed:boolean};
async function api<T>(token:string,path:string,method="GET",body?:unknown,key?:string):Promise<T>{
 const response=await fetch(BASE+path,{method,headers:{"authorization":"Bearer "+token,...(body===undefined?{}:{"content-type":"application/json"}),...(key?{"idempotency-key":key}:{})},
  ...(body===undefined?{}:{body:JSON.stringify(body)})});
 const payload=await response.json() as T&{error?:string};
 if(!response.ok)throw new Error(payload.error||"REQUEST_FAILED");
 return payload;
}
export function PtConsole({token,targetId,active}:{token:string;targetId:string;active:boolean}){
 const [versions,setVersions]=useState<Version[]>([]);
 const [specId,setSpecId]=useState("");
 const [operations,setOperations]=useState<Op[]>([]);
 const [selected,setSelected]=useState<string[]>([]);
 const [excluded,setExcluded]=useState<string[]>([]);
 const [maxEvaluations,setMaxEvaluations]=useState(6);
 const [rate,setRate]=useState(10);
 const [concurrency,setConcurrency]=useState(1);
 const [scopeId,setScopeId]=useState("");
 const [scope,setScope]=useState<Detail|null>(null);
 const [jobId,setJobId]=useState("");
 const [job,setJob]=useState<Job|null>(null);
 const [receipts,setReceipts]=useState<Receipt[]>([]);
 const [report,setReport]=useState<Report|null>(null);
 const [history,setHistory]=useState<{id:string;status:string}[]>([]);
 const [stop,setStop]=useState(false);
 const [error,setError]=useState("");
 const [status,setStatus]=useState("");
 const [busy,setBusy]=useState(false);
 const run=async(fn:()=>Promise<void>)=>{
  setBusy(true);setError("");
  try{await fn();}catch(e){setError(e instanceof Error?e.message:"PT_REQUEST_FAILED");}
  finally{setBusy(false);}
 };
 const refreshVersions=useCallback(async()=>{
  const list=await api<Version[]>(token,"/v2/targets/"+targetId+"/specifications?limit=100");
  setVersions(list);
 },[token,targetId]);
 useEffect(()=>{setVersions([]);setSpecId("");setOperations([]);setSelected([]);setScopeId("");setScope(null);setJobId("");setJob(null);
  if(token&&targetId)void refreshVersions().catch(e=>setError(String(e)));
 },[targetId,token,refreshVersions]);
 useEffect(()=>{
  let live=true;
  setOperations([]);setSelected([]);
  if(specId)void api<Op[]>(token,"/v2/specifications/"+specId+"/operations?limit=100").then(ops=>{
   if(live){setOperations(ops);setSelected(ops.filter(o=>(o.method==="GET"||o.method==="HEAD")&&["/bills","/status"].includes(o.path)).map(o=>o.key));}
  }).catch(e=>{if(live)setError(String(e));});
  return ()=>{live=false;};
 },[specId,token]);
 const refreshScope=useCallback(async()=>{
  if(!scopeId)return;
  setScope(await api<Detail>(token,"/v6/pt/scopes/"+scopeId));
 },[scopeId,token]);
 const refreshJob=useCallback(async()=>{
  if(!jobId)return;
  const j=await api<Job>(token,"/v6/pt/jobs/"+jobId);
  setJob(j);
  setReceipts(await api<Receipt[]>(token,"/v6/pt/jobs/"+jobId+"/receipts"));
  if(j.status==="COMPLETED"||j.status==="FAILED"){
   try{setReport(await api<Report>(token,"/v6/pt/jobs/"+jobId+"/report"));}
   catch{setReport(null);}
  }
 },[jobId,token]);
 const refreshHistory=useCallback(async()=>{
  if(!targetId)return;
  setHistory(await api<{id:string;status:string}[]>(token,"/v6/pt/targets/"+targetId+"/history"));
  const s=await api<{enabled:boolean}>(token,"/v6/pt/stop");
  setStop(s.enabled);
 },[targetId,token]);
 useEffect(()=>{
  if(!jobId)return;
  void refreshJob().catch(e=>setError(String(e)));
  if(job?.status==="COMPLETED"||job?.status==="FAILED"||job?.status==="CANCELLED")return;
  const timer=setInterval(()=>void refreshJob().catch(e=>setError(String(e))),1500);
  return ()=>clearInterval(timer);
 },[jobId,job?.status,refreshJob]);
 const eligible=operations.filter(o=>(o.method==="GET"||o.method==="HEAD")&&["/bills","/status"].includes(o.path));
 async function propose(){
  await run(async()=>{
   const response=await api<Scope>(token,"/v6/pt/targets/"+targetId+"/scopes","POST",{
    specificationId:specId,operationKeys:selected,exclusions:excluded,fixtureId:"billing-safe-v1",
    maxEvaluations,maxConcurrency:concurrency,ratePerMinute:rate,deadlineMs:15000,validityMinutes:10
   },"pt6-scope-"+crypto.randomUUID());
   setScopeId(response.id);setScope(null);setStatus("CUSTOMER_PROPOSED");setJobId("");setJob(null);setReceipts([]);setReport(null);
  });
 }
 async function requestAuthorization(){
  await run(async()=>{
   await api(token,"/v6/pt/scopes/"+scopeId+"/request-authorization","POST");
   await refreshScope();setStatus("PENDING_TEST_AUTHORITY");
  });
 }
 async function startJob(){
  await run(async()=>{
   if(!scope)throw new Error("SCOPE_DETAILS_NOT_LOADED");
   const x=await api<{id:string}>(token,"/v6/pt/scopes/"+scopeId+"/jobs","POST",
    {operationKeys:scope.scope.operation_keys},"pt6-job-"+crypto.randomUUID());
   setJobId(x.id);setJob(null);setStatus("QUEUED");
  });
 }
 async function cancelJob(){
  if(!window.confirm("Cancel this synthetic fixture job?"))return;
  await run(async()=>{
   await api(token,"/v6/pt/jobs/"+jobId+"/cancel","POST");
   await refreshJob();setStatus("CANCELLED");
  });
 }
 return <section role="region" aria-label="API Penetration Testing authorization and safe execution">
  <h2>API Penetration Testing — Authorization & Safe Execution</h2>
  <p><strong>Phase 06 · Synthetic fixture only.</strong> Real Host authorization is BLOCKED. No customer API requests, production exploitation or vulnerability detection.</p>
  {error&&<p role="alert" className="error">PT denied or failed: {error}</p>}
  {status&&<p role="status">PT workflow: {status}</p>}
  <p>Trusted fixture: <code>billing-safe-v1</code> · GET/HEAD only · Emergency stop: <strong>{stop?"ACTIVE":"Not active (last fetched)"}</strong></p>
  <button type="button" className="secondary" onClick={()=>void run(async()=>{await refreshVersions();await refreshHistory();})} disabled={busy}>Refresh imported versions & PT history</button>
  <label htmlFor="pt-spec-version">Imported specification for PT</label>
  <select id="pt-spec-version" value={specId} onChange={e=>setSpecId(e.target.value)} disabled={busy}>
   <option value="">Choose imported specification</option>
   {versions.map(v=><option key={v.specificationId} value={v.specificationId}>v{v.version} · {v.format} · {v.specificationId.slice(0,8)}</option>)}
  </select>
  {specId&&<><h3>1. Customer-proposed immutable testing scope</h3>
   <p>Choosing a target or selecting operations does not authorize execution. This scope requires independently trusted synthetic authorization.</p>
   {eligible.length===0&&<p>No GET/HEAD operations compatible with the trusted fixture catalog.</p>}
   <fieldset><legend>Allowed fixture operations</legend>
    {eligible.map(op=><label key={op.key}><input type="checkbox" checked={selected.includes(op.key)} onChange={e=>setSelected(x=>e.target.checked?[...x,op.key]:x.filter(k=>k!==op.key))}/>{op.method} {op.path} ({op.key})</label>)}
   </fieldset>
   <fieldset><legend>Explicit path exclusions</legend>
    {["/bills","/status"].map(p=><label key={p}><input type="checkbox" checked={excluded.includes(p)} onChange={e=>setExcluded(x=>e.target.checked?[...x,p]:x.filter(k=>k!==p))}/>Exclude {p}</label>)}
   </fieldset>
   <div className="formgrid">
    <label>Maximum fixture evaluations<input type="number" min={1} max={30} value={maxEvaluations} onChange={e=>setMaxEvaluations(Number(e.target.value))}/></label>
    <label>Rate per minute<input type="number" min={1} max={20} value={rate} onChange={e=>setRate(Number(e.target.value))}/></label>
    <label>Maximum concurrent jobs<input type="number" min={1} max={2} value={concurrency} onChange={e=>setConcurrency(Number(e.target.value))}/></label>
   </div>
   <button disabled={!active||busy||selected.length===0} onClick={()=>void propose()}>Propose immutable PT scope</button>
  </>}
  {scopeId&&<><h3>2. Authorization boundary</h3>
   <p>Scope identity: <code>{scopeId}</code></p>
   <button type="button" disabled={busy} className="secondary" onClick={()=>void run(refreshScope)}>Refresh authorization and permit state</button>
   <button type="button" disabled={busy} onClick={()=>void requestAuthorization()}>Request synthetic PT authorization</button>
   {scope&&<><p>Authorization requested: {scope.requested?"YES":"NO"} · Real Host execution: <strong>{scope.realHostExecution}</strong></p>
    {scope.permit?
     <p>Test-only permit: <code>{scope.permit.id}</code> · {scope.permit.revoked?"REVOKED":scope.permit.expired?"EXPIRED":"SYNTHETIC FIXTURE PERMIT"} · Expires {scope.permit.expiresAt}. Consumed {scope.permit.consumed}, reserved {scope.permit.reserved} of {scope.scope.max_evaluations}.</p>:
     <p role="status">No permit. Execution will be denied until the separate trusted test authority approves. The browser cannot issue or sign permits.</p>}
    <button type="button" disabled={busy} onClick={()=>void startJob()}>Attempt bounded fixture execution</button>
   </>}
  </>}
  {jobId&&<><h3>3. Private worker execution</h3>
   <p>Job <code>{jobId}</code> · Status <strong>{job?.status??"Loading"}</strong> · Customer-target HTTP requests: 0</p>
   {job?.errorCode&&<p role="alert">Execution failed: {job.errorCode}</p>}
   <button className="secondary" type="button" onClick={()=>void run(refreshJob)} disabled={busy}>Refresh worker receipts</button>
   {job&&["QUEUED","PROCESSING"].includes(job.status)&&<button className="secondary" disabled={busy} onClick={()=>void cancelJob()}>Cancel fixture job</button>}
   {job&&<p>Budget used: {job.consumed} · Reserved: {job.reserved} · Remaining: {Math.max(0,job.max_evaluations-job.consumed-job.reserved)} · Allowed: {job.counts.ALLOWED??0} · Denied: {job.counts.DENIED??0} · Skipped: {job.counts.SKIPPED??0}</p>}
   {receipts.length>0&&<div style={{overflowX:"auto"}}><table><caption>Persisted immutable evaluation receipts</caption><thead><tr><th>Operation</th><th>Authorization</th><th>Outcome</th><th>Status</th><th>Budget</th></tr></thead>
    <tbody>{receipts.map(x=><tr key={x.id}><td>{x.method} {x.path}</td><td>{x.decision}</td><td>{x.code}</td><td>{x.http_status??"No HTTP"}</td><td>{x.budget_consumed}</td></tr>)}</tbody>
   </table></div>}
   {report&&<article className="finding"><h4>Immutable PT authorization and fixture execution report</h4>
    <p>{report.status} · Allowed {report.counts.allowed} · Denied {report.counts.denied} · Skipped {report.counts.skipped} · Customer requests {report.customerNetworkRequests}</p>
    <p>Synthetic-only: {String(report.syntheticOnly)} · VERIFIED_FIXED: {String(report.verifiedFixed)}</p>
    <ul>{report.limitations.map(x=><li key={x}>{x}</li>)}</ul>
   </article>}
  </>}
  <h3>4. Historical PT fixture runs</h3>
  <button type="button" className="secondary" onClick={()=>void run(refreshHistory)} disabled={busy}>Refresh PT history and emergency status</button>
  {history.map(x=><p key={x.id}><button className="secondary" type="button" onClick={()=>{setJobId(x.id);setJob(null);setReceipts([]);setReport(null);}}>Inspect run {x.id.slice(0,8)} · {x.status}</button></p>)}
  <p><small>Permit revocation, issuance and emergency stop are reserved to the separate trusted test authority, never customer-controlled browser actions. No production signing keys or network transports are exposed.</small></p>
 </section>;
}
