import {useCallback,useEffect,useState} from "react";

const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
type Version={specificationId:string;version:number;format:string;normalizedFingerprint:string};
type Run={id:string;targetId:string;targetName:string;environment:string;specificationId:string;specificationVersion:number|null;format:string;engineVersion:string;status:string;errorCode?:string;createdAt:string;completedAt?:string};
type Finding={id:string;ruleId:string;ruleVersion:string|null;operationKey:string|null;category:string;impact:string|null;confidence:string|null;explanation:string;remediation:string;observationType:string;validationLevel:string;reviewRequired:boolean;sourcePointer:string;fingerprint:string|null};
type Detail=Finding&{evidence:Record<string,unknown>;potentialImpact:string|null;notice:string};
type Coverage={rules:{ruleId:string;ruleVersion:string;status:string|null;skipReason:string|null;matchCount:number|null}[];limitations:string[];warnings:string[];operationsEvaluated:number|null;notice:string};
type Comparison={comparable:boolean;reason:string|null;counts?:Record<string,number>;newlyObserved:Finding[];noLongerObserved:Finding[];stillObserved:Finding[];evidenceChanged:Finding[];notice:string;syntheticFixtureOnly?:boolean};
type Report={schemaVersion:string;assessment:Run;immutableReport:Record<string,unknown>;provenance:Record<string,unknown>;notice:string};
async function api<T>(token:string,path:string,method="GET",body?:unknown,headers:Record<string,string>={}):Promise<T>{
 const response=await fetch(BASE+path,{method,headers:{authorization:"Bearer "+token,"content-type":"application/json",...headers},
  ...(body===undefined?{}:{body:JSON.stringify(body)})});
 const result:unknown=await response.json();
 if(!response.ok)throw new Error((result as {error?:string}).error??"API_REQUEST_FAILED");
 return result as T;
}
const catalog:{id:string;label:string;guide:string;section:string}[]=[
 {id:"inventory-v1",label:"Specification Security Assessment",guide:"Offline declarations only. No runtime security conclusions.",section:"#api-inventory-analysis"},
 {id:"inventory-v2",label:"Richer Offline Specification Analysis",guide:"Versioned phase05-v2 metadata only. Six additional declaration checks; older imports remain v1.",section:"#api-inventory-analysis"},
 {id:"auth-fixture-v1",label:"Synthetic Authentication & Authorization Validation",guide:"Only trusted test fixtures. Not customer API authentication.",section:"#api-auth-fixture"}
];
export function UnifiedAssessment({token,targetId}:{token:string;targetId:string}){
 const [engine,setEngine]=useState("inventory-v1"),[status,setStatus]=useState(""),[offset,setOffset]=useState(0);
 const [versions,setVersions]=useState<Version[]>([]),[specification,setSpecification]=useState(""),[newJob,setNewJob]=useState("");
 const [runs,setRuns]=useState<Run[]>([]),[selected,setSelected]=useState<Run|null>(null);
 const [findings,setFindings]=useState<Finding[]>([]),[findingPage,setFindingPage]=useState(0),[rule,setRule]=useState("");
 const [impact,setImpact]=useState(""),[confidence,setConfidence]=useState(""),[search,setSearch]=useState("");
 const [detail,setDetail]=useState<Detail|null>(null),[coverage,setCoverage]=useState<Coverage|null>(null),[report,setReport]=useState<Report|null>(null);
 const [from,setFrom]=useState(""),[to,setTo]=useState(""),[comparison,setComparison]=useState<Comparison|null>(null);
 const [error,setError]=useState(""),[busy,setBusy]=useState(false),[loading,setLoading]=useState(false);
 const refresh=useCallback(async()=>{
  if(!token){setRuns([]);return;}
  const q=new URLSearchParams({limit:"20",offset:String(offset)});
  if(targetId)q.set("targetId",targetId);
  if(status)q.set("status",status);
  const data=await api<Run[]>(token,"/v5/assessments?"+q.toString());
  setRuns(data);
 },[token,targetId,status,offset]);
 useEffect(()=>{let live=true;setLoading(true);setError("");
  void refresh().catch(e=>{if(live)setError(e instanceof Error?e.message:"HISTORY_UNAVAILABLE");}).finally(()=>{if(live)setLoading(false);});
  return()=>{live=false;};
 },[refresh]);
 useEffect(()=>{setSelected(null);setDetail(null);setCoverage(null);setReport(null);setFindings([]);setComparison(null);setFrom("");setTo("");setNewJob("");setVersions([]);
   if(!targetId||!token)return;
   let live=true;
   void api<Version[]>(token,"/v2/targets/"+targetId+"/specifications?limit=100")
     .then(v=>{if(live){setVersions(v);setSpecification(v[0]?.specificationId??"");}})
     .catch(e=>{if(live)setError(e instanceof Error?e.message:"VERSIONS_UNAVAILABLE");});
   return()=>{live=false;};
 },[targetId,token]);
 useEffect(()=>{if(!selected||selected.status!=="COMPLETED"){setFindings([]);setCoverage(null);setReport(null);return;}
  let live=true;const q=new URLSearchParams({limit:"25",offset:String(findingPage)});
  if(rule)q.set("ruleId",rule);if(impact)q.set("impact",impact);if(confidence)q.set("confidence",confidence);if(search)q.set("search",search);
  void Promise.all([
    api<Finding[]>(token,"/v5/assessments/"+selected.id+"/findings?"+q),
    api<Coverage>(token,"/v5/assessments/"+selected.id+"/coverage")
  ]).then(([f,c])=>{if(live){setFindings(f);setCoverage(c);}})
    .catch(e=>{if(live)setError(e.message);});
  return()=>{live=false;};
 },[selected?.id,selected?.status,token,findingPage,rule,impact,confidence,search]);
 async function run(fn:()=>Promise<void>){setBusy(true);setError("");try{await fn();}catch(e){setError(e instanceof Error?e.message:"REQUEST_FAILED");}finally{setBusy(false);}}
 async function reloadVersions(){
  if(!targetId)return;
  const v=await api<Version[]>(token,"/v2/targets/"+targetId+"/specifications?limit=100");
  setVersions(v);setSpecification(old=>v.some(x=>x.specificationId===old)?old:(v[0]?.specificationId??""));
 }
 async function cancelRun(){
  if(!selected||!["inventory-v1","inventory-v2"].includes(selected.engineVersion))return;
  await run(async()=>{
   await api(token,"/v5/assessments/"+selected.id+"/cancel","POST");
   setSelected({...selected,status:"CANCELLED"});await refresh();
  });
 }
 async function startAssessment(){
  if(!targetId||!specification||engine==="auth-fixture-v1")return;
  await run(async()=>{
   const entry=await api<{id:string;status:string}>(token,"/v5/targets/"+targetId+"/assessments","POST",
    {engineVersion:engine,mode:"SPEC_ONLY",specificationId:specification},
    {"idempotency-key":"phase05-ui-"+crypto.randomUUID()});
   setNewJob(entry.id+" · "+entry.status+" · awaiting private worker");await refresh();
  });
 }
 async function openRun(item:Run){
  setSelected(item);setReport(null);setDetail(null);setFindingPage(0);setRule("");setSearch("");setImpact("");setConfidence("");
  if(item.status==="COMPLETED")await run(async()=>{setReport(await api<Report>(token,"/v5/assessments/"+item.id+"/report"));});
 }
 async function openDetail(id:string){if(!selected)return;
  await run(async()=>setDetail(await api<Detail>(token,"/v5/assessments/"+selected.id+"/findings/"+id)));
 }
 async function compare(){if(!from||!to||from===to)return;
  await run(async()=>setComparison(await api<Comparison>(token,"/v5/assessments/compare","POST",{fromAssessmentId:from,toAssessmentId:to})));
 }
 async function exportReport(){if(!selected||!report)return;
  await run(async()=>{
   const response=await fetch(BASE+"/v5/assessments/"+selected.id+"/export",{headers:{authorization:"Bearer "+token}});
   if(!response.ok)throw new Error("EXPORT_DENIED_OR_TOO_LARGE");
   const blob=await response.blob(),url=URL.createObjectURL(blob),link=document.createElement("a");
   link.href=url;link.download="lumicsec-api-"+selected.id+".json";link.click();URL.revokeObjectURL(url);
  });
 }
 const available=runs.filter(x=>x.status==="COMPLETED");
 return <section role="region" aria-label="Unified assessment workspace" id="api-assessment-workspace">
  <h2>API Assessment Workspace</h2>
  <p>One workspace for specification security, synthetic fixture validation, findings, limitations, reports and historical comparison. No live probing or Host authorization.</p>
  <h3>New assessment</h3>
  <label>Assessment type<select value={engine} onChange={e=>setEngine(e.target.value)}>
   {catalog.map(c=><option key={c.id} value={c.id}>{c.label}</option>)}
  </select></label>
  <p>{catalog.find(x=>x.id===engine)?.guide}</p>
  {targetId&&engine!=="auth-fixture-v1"&&<>
   <button className="secondary" disabled={busy} onClick={()=>void run(reloadVersions)}>Refresh imported specification versions</button>
   <label>Imported immutable specification<select value={specification} onChange={e=>setSpecification(e.target.value)}>
    {versions.length===0&&<option value="">Import a specification first</option>}
    {versions.map(v=><option key={v.specificationId} value={v.specificationId}>Version {v.version} · {v.format}</option>)}
   </select></label>
   <button className="secondary" disabled={busy||!specification} onClick={()=>void startAssessment()}>Start selected offline assessment</button>
   {newJob&&<p role="status">Queued assessment: {newJob}</p>}
  </>}
  {targetId?<a href={catalog.find(x=>x.id===engine)?.section}>{engine==="auth-fixture-v1"?"Configure validated synthetic fixture assessment":"Import or inspect specification using preserved controls"}</a>:
   <p>Select an API target above to configure an assessment.</p>}
  <p>Engine choice does not confer ownership, production credentials or target-network permission.</p>
  <h3>Assessment runs and history</h3>
  <div className="formgrid">
   <label>Run status<select value={status} onChange={e=>{setStatus(e.target.value);setOffset(0);}}>
    <option value="">All states</option>{["QUEUED","PROCESSING","COMPLETED","FAILED","CANCELLED"].map(x=><option key={x} value={x}>{x[0]+x.slice(1).toLowerCase()} runs</option>)}
   </select></label>
  </div>
  <button className="secondary" disabled={busy||loading} onClick={()=>void run(refresh)}>Refresh assessment history</button>
  {loading&&<p role="status">Loading persisted assessment history…</p>}
  {error&&!["PERMISSION_DENIED","UNAUTHORIZED"].includes(error)&&<p role="alert">{error}</p>}
  {!loading&&runs.length===0&&<p>No persisted assessments match these filters.</p>}
  <div style={{overflowX:"auto"}}><table><thead><tr><th>Target</th><th>Specification</th><th>Assessment engine</th><th>Status</th><th>Open</th></tr></thead>
   <tbody>{runs.map(item=><tr key={item.id}><td>{item.targetName}</td><td>v{item.specificationVersion??"legacy"} / {item.format}</td><td>{item.engineVersion}</td>
    <td>{item.status}</td><td><button className="secondary" onClick={()=>void openRun(item)}>Review run</button></td></tr>)}</tbody>
  </table></div>
  <button className="secondary" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-20))}>Previous runs</button>
  <button className="secondary" disabled={runs.length<20} onClick={()=>setOffset(offset+20)}>Next runs</button>
  {selected&&<article className="finding">
   <h3>Assessment detail</h3>
   <p>{selected.id} · {selected.engineVersion} · {selected.status}</p>
   {selected.errorCode&&<p role="alert">Failure code: {selected.errorCode}</p>}
   {["QUEUED","PROCESSING"].includes(selected.status)&&["inventory-v1","inventory-v2"].includes(selected.engineVersion)&&
    <button className="secondary" disabled={busy} onClick={()=>void cancelRun()}>Cancel pending assessment</button>}
   <p>Specification: {selected.specificationId} · Version: {selected.specificationVersion??"historical"}</p>
   {selected.status!=="COMPLETED"&&<p>This assessment has no completed report. A new valid assessment can be started using the configuration above.</p>}
   {report&&<><h4>Immutable report</h4><p>{report.schemaVersion} · Validated as {String(report.provenance.validationLevel)}.</p>
    <p>Historical results are observations, not confirmed production vulnerabilities or verified fixes.</p>
    <button className="secondary" onClick={()=>void exportReport()}>Export persisted JSON report</button>
    <button className="secondary" onClick={()=>window.print()}>Print assessment report</button>
    <details><summary>View report provenance</summary><pre>{JSON.stringify(report.provenance,null,2)}</pre></details>
   </>}
   {coverage&&<><h4>Coverage and unknowns</h4>
    <p>{coverage.rules.filter(x=>x.status==="EVALUATED").length} rule results evaluated; {coverage.rules.filter(x=>x.status==="SKIPPED").length} skipped entries. Runtime security not verified.</p>
    <details><summary>Inspect executed / skipped rule results</summary><table><thead><tr><th>Rule</th><th>Status</th><th>Reason</th></tr></thead><tbody>
     {coverage.rules.map((r,i)=><tr key={i}><td>{r.ruleId}</td><td>{r.status??"HISTORICAL"}</td><td>{r.skipReason??"—"}</td></tr>)}</tbody></table></details>
    <ul>{[...coverage.warnings,...coverage.limitations].map((v,i)=><li key={i}>{v}</li>)}</ul>
   </>}
   {selected.status==="COMPLETED"&&<><h4>Unified findings</h4>
    <div className="formgrid">
     <label>Findings search<input value={search} onChange={e=>{setSearch(e.target.value);setFindingPage(0);}} placeholder="Rule or operation"/></label>
     <label>Rule ID<input value={rule} onChange={e=>{setRule(e.target.value);setFindingPage(0);}} placeholder="Rule ID"/></label>
     <label>Impact<select value={impact} onChange={e=>{setImpact(e.target.value);setFindingPage(0);}}><option value="">All</option>{["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL_CANDIDATE"].map(x=><option key={x}>{x}</option>)}</select></label>
     <label>Confidence<select value={confidence} onChange={e=>{setConfidence(e.target.value);setFindingPage(0);}}><option value="">All</option>{["HIGH","MEDIUM","LOW"].map(x=><option key={x}>{x}</option>)}</select></label>
    </div>
    {findings.length===0&&<p>No observations returned by these executed rules and filters. Runtime security remains UNKNOWN.</p>}
    <table><thead><tr><th>Rule</th><th>Operation</th><th>Evidence classification</th><th>Detail</th></tr></thead><tbody>
    {findings.map(f=><tr key={f.id}><td>{f.ruleId}</td><td>{f.operationKey??"Document"}</td><td>{f.observationType}</td>
     <td><button className="secondary" onClick={()=>void openDetail(f.id)}>View persisted evidence</button></td></tr>)}
    </tbody></table>
    <button className="secondary" disabled={findingPage===0} onClick={()=>setFindingPage(Math.max(0,findingPage-25))}>Previous findings page</button>
    <button className="secondary" disabled={findings.length<25} onClick={()=>setFindingPage(findingPage+25)}>Next findings page</button>
    {detail&&<section><h4>Finding evidence: {detail.ruleId}</h4>
     <p>{detail.explanation}</p><p>Potential impact: {detail.potentialImpact??"Unverified"} · Source: <code>{detail.sourcePointer}</code></p>
     <p>Recommended action: {detail.remediation}</p>
     <p>Validation: {detail.validationLevel} · Review required: {String(detail.reviewRequired)}</p>
     <details><summary>Persisted evidence details</summary><pre>{JSON.stringify(detail.evidence,null,2)}</pre></details>
     <p>Fix applied does not mean VERIFIED_FIXED.</p>
    </section>}
   </>}
  </article>}
  <h3>History comparison</h3>
  <div className="formgrid">
   <label>Baseline completed run<select value={from} onChange={e=>setFrom(e.target.value)}><option value="">Select baseline</option>
    {available.map(r=><option value={r.id} key={r.id}>{r.engineVersion} · v{r.specificationVersion??"?"} · {r.id.slice(0,8)}</option>)}
   </select></label>
   <label>New completed run<select value={to} onChange={e=>setTo(e.target.value)}><option value="">Select comparison</option>
    {available.map(r=><option value={r.id} key={r.id}>{r.engineVersion} · v{r.specificationVersion??"?"} · {r.id.slice(0,8)}</option>)}
   </select></label>
  </div>
  <button className="secondary" disabled={!from||!to||from===to||busy} onClick={()=>void compare()}>Compare persisted findings</button>
  {comparison&&<article className="finding"><h4>Comparison results</h4>
   {!comparison.comparable?<p>Comparison unavailable: {comparison.reason}. No fix claims are inferred.</p>:
    <><p>Newly observed: {comparison.counts?.newlyObserved} · Still observed: {comparison.counts?.stillObserved} · No longer observed: {comparison.counts?.noLongerObserved} · Evidence changed: {comparison.counts?.evidenceChanged}</p>
     {comparison.syntheticFixtureOnly&&<p>This comparison concerns synthetic fixtures only, never customer API vulnerabilities.</p>}
     <ul>{comparison.newlyObserved.map(x=><li key={x.fingerprint}>Newly observed {x.ruleId}: {x.operationKey}</li>)}
      {comparison.noLongerObserved.map(x=><li key={x.fingerprint}>No longer observed {x.ruleId}: {x.operationKey}</li>)}
      {comparison.evidenceChanged.map(x=><li key={x.fingerprint}>Evidence changed {x.ruleId}: {x.operationKey}</li>)}</ul></>}
   <p>No longer observed never means VERIFIED_FIXED.</p>
  </article>}
  <p>UNKNOWN != SAFE · NO EVIDENCE != SAFE · CI PASS != VERIFIED_FIXED</p>
 </section>;
}
