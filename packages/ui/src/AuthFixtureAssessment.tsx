import React,{useEffect,useState} from "react";
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
const NOTICE="SYNTHETIC AUTHENTICATED ASSESSMENT — NOT REAL HOST AUTHORIZATION OR CUSTOMER RUNTIME VERIFICATION.";
type Version={specificationId:string;version:number;format:string};
type Credential={id:string;reference:string;status:string};
type Profile={id:string;specificationId:string;fixtureVersion:string;scheme:string;identityKey:string;role:string;revision:number;credentialReference:string;status:string;validationStatus:string};
type Assessment={id:string;status:string;errorCode?:string;fixtureVersion?:string};
type Evaluation={id:string;ruleId:string;identity:string;role:string;operationKey:string;expected:string;observed:string;status:number;result:string;fingerprint:string};
type Finding={id:string;ruleId:string;operationKey:string;explanation:string;remediation:string;evidenceId:string;evidence:Record<string,unknown>};
type Report={assessmentId:string;fixtureVersion:string;scheme:string;observationCount:number;evaluationCount:number;coverage:{attempted:number;passed:number;deviations:number;unknown:number;unsupportedDeclaredSchemes:number;untestedCustomerOperations:boolean};declaredSchemes:{name:string;status:string;fixtureScheme?:string}[];limitations:string[];customerNetworkRequests:number;confirmedCustomerVulnerabilities:unknown[]};
type Comparison={newlyObserved:string[];noLongerObserved:string[];stillObserved:string[]};
async function api<T>(token:string,path:string,method="GET",body?:unknown,idem?:string):Promise<T>{
 const r=await fetch(BASE+path,{method,headers:{"authorization":"Bearer "+token,"content-type":"application/json",...(idem?{"idempotency-key":idem}:{})},body:body===undefined?undefined:JSON.stringify(body)});
 const data:unknown=await r.json();
 if(!r.ok)throw Error((data as {error?:string}).error??"AUTH_FIXTURE_REQUEST_FAILED");
 return data as T;
}
const randomKey=(prefix:string)=>prefix+"-"+crypto.randomUUID();
export function AuthFixtureAssessment({token,targetId,active,revision}:{token:string;targetId:string;active:boolean;revision:number}){
 const [versions,setVersions]=useState<Version[]>([]);
 const [credentials,setCredentials]=useState<Credential[]>([]);
 const [profiles,setProfiles]=useState<Profile[]>([]);
 const [history,setHistory]=useState<Assessment[]>([]);
 const [specId,setSpecId]=useState("");
 const [declared,setDeclared]=useState<{name:string;type:string;scheme?:string}[]>([]);
 const [reference,setReference]=useState("credref:phase04_fixture");
 const [fixture,setFixture]=useState("secure-v1");
 const [scheme,setScheme]=useState("BEARER");
 const [identity,setIdentity]=useState("user-a");
 const [profileId,setProfileId]=useState("");
 const [job,setJob]=useState<Assessment|null>(null);
 const [evaluations,setEvaluations]=useState<Evaluation[]>([]);
 const [findings,setFindings]=useState<Finding[]>([]);
 const [report,setReport]=useState<Report|null>(null);
 const [filter,setFilter]=useState("ALL");
 const [detail,setDetail]=useState<Record<string,unknown>|null>(null);
 const [compareId,setCompareId]=useState("");
 const [comparison,setComparison]=useState<Comparison|null>(null);
 const [error,setError]=useState("");
 const [busy,setBusy]=useState(false);
 const [message,setMessage]=useState("");
 const selected=profiles.find(x=>x.id===profileId);
 async function load(){
  const [v,c,p,h]=await Promise.all([
   api<Version[]>(token,"/v2/targets/"+targetId+"/specifications?limit=100"),
   api<Credential[]>(token,"/v1/targets/"+targetId+"/credentials"),
   api<Profile[]>(token,"/v4/targets/"+targetId+"/profiles?limit=100"),
   api<Assessment[]>(token,"/v4/targets/"+targetId+"/assessments?limit=100")]);
  setVersions(v);setCredentials(c);setProfiles(p);setHistory(h);
  setSpecId(s=>v.some(x=>x.specificationId===s)?s:v[0]?.specificationId??"");
  setProfileId(s=>p.some(x=>x.id===s)?s:p[0]?.id??"");
 }
 useEffect(()=>{
  let alive=true;
  setVersions([]);setCredentials([]);setProfiles([]);setHistory([]);setJob(null);setReport(null);
  void Promise.all([
   api<Version[]>(token,"/v2/targets/"+targetId+"/specifications?limit=100"),
   api<Credential[]>(token,"/v1/targets/"+targetId+"/credentials"),
   api<Profile[]>(token,"/v4/targets/"+targetId+"/profiles?limit=100"),
   api<Assessment[]>(token,"/v4/targets/"+targetId+"/assessments?limit=100")])
   .then(([v,c,p,h])=>{if(alive){setVersions(v);setCredentials(c);setProfiles(p);setHistory(h);setSpecId(v[0]?.specificationId??"");setProfileId(p[0]?.id??"");}})
   .catch(e=>{if(alive)setError((e as Error).message);});
  return()=>{alive=false;};
 },[targetId,token]);
 useEffect(()=>{
  let alive=true;setDeclared([]);
  if(specId)void api<{name:string;type:string;scheme?:string}[]>(token,"/v2/specifications/"+specId+"/schemes")
   .then(r=>{if(alive)setDeclared(Array.isArray(r)?r:Object.entries(r).map(([name,v])=>({name,...v})));})
   .catch(e=>{if(alive)setError((e as Error).message);});
  return()=>{alive=false;};
 },[specId,token]);
 useEffect(()=>{
  if(!job||!["QUEUED","PROCESSING"].includes(job.status))return;
  let alive=true;
  const tick=()=>void api<Assessment>(token,"/v4/assessments/"+job.id).then(x=>{if(alive)setJob(x);}).catch(e=>{if(alive)setError((e as Error).message);});
  const timer=setInterval(tick,1200);tick();
  return()=>{alive=false;clearInterval(timer);};
 },[job?.id,job?.status,token]);
 useEffect(()=>{
  let alive=true;setReport(null);setEvaluations([]);setFindings([]);setDetail(null);
  if(job?.status==="COMPLETED")void Promise.all([
    api<Report>(token,"/v4/assessments/"+job.id+"/report"),
    api<Evaluation[]>(token,"/v4/assessments/"+job.id+"/evaluations?limit=100"),
    api<Finding[]>(token,"/v4/assessments/"+job.id+"/findings?limit=100")])
   .then(([r,e,f])=>{if(alive){setReport(r);setEvaluations(e);setFindings(f);}})
   .catch(e=>{if(alive)setError((e as Error).message);});
  return()=>{alive=false;};
 },[job?.id,job?.status,token]);
 async function act(task:()=>Promise<void>){
  setBusy(true);setError("");setMessage("");
  try{await task();}catch(e){setError(e instanceof Error?e.message:"AUTH_FIXTURE_FAILED");}finally{setBusy(false);}
 }
 const createReference=()=>act(async()=>{
  if(!/^credref:[a-zA-Z0-9_-]{4,128}$/.test(reference))throw Error("OPAQUE_REFERENCE_FORMAT_REQUIRED");
  await api(token,"/v1/targets/"+targetId+"/credentials","POST",{revision,reference});
  await load();setMessage("Opaque reference registered. No credential value was stored or retrieved.");
 });
 const createProfile=()=>act(async()=>{
  const result=await api<Profile>(token,"/v4/targets/"+targetId+"/profiles","POST",
   {specificationId:specId,fixtureVersion:fixture,scheme,identityKey:identity,credentialReference:reference});
  await load();setProfileId(result.id);setMessage("Synthetic profile created; validate before starting.");
 });
 const validate=()=>act(async()=>{
  if(!selected)return;
  const r=await api<{ready:boolean;reasons:string[]}>(token,"/v4/profiles/"+selected.id+"/validate","POST",{revision:selected.revision});
  await load();setMessage(r.ready?"Fixture-ready: trusted synthetic configuration only.":"Not ready: "+r.reasons.join(", "));
 });
 const rotate=()=>act(async()=>{
  if(!selected)return;
  await api(token,"/v4/profiles/"+selected.id,"PATCH",{revision:selected.revision,credentialReference:reference,
   fixtureVersion:fixture,scheme,identityKey:identity});
  await load();setMessage("New profile revision requires fresh validation.");
 });
 const revoke=()=>act(async()=>{
  if(!selected)return;
  await api(token,"/v4/profiles/"+selected.id+"/revoke","POST",{revision:selected.revision});
  await load();setMessage("Synthetic profile revoked.");
 });
 const start=()=>act(async()=>{
  if(!selected||selected.specificationId!==specId)throw Error("PROFILE_SPECIFICATION_MISMATCH");
  const r=await api<Assessment>(token,"/v4/targets/"+targetId+"/assessments","POST",
   {specificationId:specId,profileId:selected.id,profileRevision:selected.revision,
    engineVersion:"auth-fixture-v1",analysisProfile:"SYNTHETIC_AUTH_FIXTURE",mode:"SPEC_ONLY"},randomKey("auth04"));
  setJob(r);setComparison(null);await load();
 });
 const cancel=()=>act(async()=>{
  if(!job)return;
  const r=await api<Assessment>(token,"/v4/assessments/"+job.id+"/cancel","POST");
  setJob(r);await load();
 });
 const view=()=>act(async()=>{
  if(!compareId)return;
  const r=await api<Assessment>(token,"/v4/assessments/"+compareId);
  setJob(r);
 });
 const compare=()=>act(async()=>{
  if(!job||!compareId)return;
  const r=await api<Comparison>(token,"/v4/targets/"+targetId+"/assessments/compare","POST",
   {fromAssessmentId:compareId,toAssessmentId:job.id});
  setComparison(r);
 });
 const evidence=(evidenceId:string)=>act(async()=>{
  if(!job)return;
  const r=await api<{content_json:Record<string,unknown>}>(token,"/v4/assessments/"+job.id+"/evidence/"+evidenceId);
  setDetail(r.content_json);
 });
 const shown=evaluations.filter(x=>filter==="ALL"||x.result===filter);
 return <section role="region" aria-label="Synthetic authenticated assessment">
  <h2>Phase 04 · Synthetic authenticated API assessment</h2><p><strong>{NOTICE}</strong></p>
  <p>Trusted in-process fixtures only · SPEC_ONLY · 0 customer HTTP requests · No Host credential retrieval.</p>
  {error&&<p role="alert" className="error">{error}</p>}
  {message&&<p role="status">{message}</p>}
  <button className="secondary" disabled={busy} onClick={()=>void act(load)}>Refresh imported versions, profiles & history</button>
  <h3>1. Imported specification and declared authentication</h3>
  <label>Specification version for synthetic authentication<select value={specId} onChange={e=>setSpecId(e.target.value)}>
   <option value="">Select an imported version</option>{versions.map(v=><option key={v.specificationId} value={v.specificationId}>v{v.version} · {v.format}</option>)}
  </select></label>
  {!versions.length&&<p>Import an OpenAPI or Postman document in the offline discovery panel first.</p>}
  {declared.length===0?<p>Declared authentication: none or unavailable. This does not establish runtime safety.</p>:
   <ul>{declared.map(s=><li key={s.name}>{s.name} · {s.type} {s.scheme??""} · declared, not production-verified</li>)}</ul>}
  <h3>2. Opaque credential reference — synthetic only</h3>
  <p>Do not enter a password, token, key or session cookie. A reference never grants access to a secret.</p>
  <label>Opaque reference<input value={reference} maxLength={145} onChange={e=>setReference(e.target.value)} placeholder="credref:phase04_fixture"/></label>
  <button disabled={busy||!active||!specId} onClick={()=>void createReference()}>Register opaque reference</button>
  <p>Bound references: {credentials.length?credentials.map(c=>c.reference).join(", "):"None"}</p>
  <h3>3. Trusted fixture, identity and test auth scheme</h3>
  <div className="formgrid">
   <label>Fixture version<select value={fixture} onChange={e=>setFixture(e.target.value)}>
    <option value="secure-v1">secure-v1 · expected enforcement</option>
    <option value="broken-bola-v1">broken-bola-v1 · deliberate synthetic defect</option>
   </select></label>
   <label>Synthetic authentication scheme<select value={scheme} onChange={e=>setScheme(e.target.value)}>
    {["BEARER","API_KEY","BASIC","OAUTH2","SESSION"].map(s=><option key={s}>{s}</option>)}
   </select></label>
   <label>Trusted identity profile<select value={identity} onChange={e=>setIdentity(e.target.value)}>
    <option value="user-a">user-a · reader</option><option value="user-b">user-b · reader</option>
    <option value="manager">manager · privileged</option><option value="admin">admin · administrator</option>
   </select></label>
  </div>
  <button disabled={busy||!active||!specId||!credentials.some(x=>x.reference===reference)} onClick={()=>void createProfile()}>Create synthetic identity profile</button>
  <label>Active synthetic profile<select value={profileId} onChange={e=>setProfileId(e.target.value)}>
   <option value="">Select test profile</option>{profiles.map(p=><option key={p.id} value={p.id}>{p.identityKey} · {p.scheme} · {p.fixtureVersion} · rev {p.revision} · {p.status}/{p.validationStatus}</option>)}
  </select></label>
  {selected&&<>
   <p>Revision {selected.revision} · {selected.role} · {selected.status} · validation: {selected.validationStatus}</p>
   <button disabled={busy||!active||selected.status!=="ACTIVE"} onClick={()=>void validate()}>Validate fixture readiness</button>
   <button className="secondary" disabled={busy||!active||selected.status!=="ACTIVE"} onClick={()=>void rotate()}>Rotate profile configuration</button>
   <button className="secondary" disabled={busy||selected.status!=="ACTIVE"} onClick={()=>void revoke()}>Revoke synthetic profile</button>
  </>}
  <h3>4. Trusted authorization policy</h3><p>user-a and user-b can read their own records; admin can read both and perform admin actions. All others are denied. The broken fixture deliberately permits user-b to read user-a's record. These policies are not inferred from the customer specification.</p>
  <button disabled={busy||!active||selected?.validationStatus!=="VALID"||selected.status!=="ACTIVE"||selected.specificationId!==specId} onClick={()=>void start()}>
   Start isolated authenticated assessment</button>
  {job&&<><p role="status">Authenticated assessment status: <strong>{job.status}</strong> {job.errorCode??""}</p>
   {["QUEUED","PROCESSING"].includes(job.status)&&<button className="secondary" onClick={()=>void cancel()}>Cancel authenticated assessment</button>}
  </>}
  <h3>5. Assessment history and deterministic comparison</h3>
  <label>Historical assessment<select value={compareId} onChange={e=>setCompareId(e.target.value)}>
   <option value="">Select previous run</option>{history.filter(h=>h.status==="COMPLETED").map(h=><option key={h.id} value={h.id}>{h.id.slice(0,8)} · {h.status}</option>)}
  </select></label>
  <button className="secondary" disabled={busy||!compareId} onClick={()=>void view()}>Open persisted historical report</button>
  <button className="secondary" disabled={busy||!compareId||job?.status!=="COMPLETED"||job.id===compareId} onClick={()=>void compare()}>Compare historical runs</button>
  {comparison&&<p>New fixture observations: {comparison.newlyObserved.length} · Resolved in fixture: {comparison.noLongerObserved.length} · Unchanged: {comparison.stillObserved.length}. Customer status remains UNKNOWN.</p>}
  {report&&<>
   <h3>6. Immutable evidence-backed synthetic report</h3>
   <p>Fixture {report.fixtureVersion} · {report.scheme} · {report.evaluationCount} real in-memory evaluations · {report.observationCount} fixture-only deviations · Customer network requests: {report.customerNetworkRequests}</p>
   <p>Expected-policy assertions passed: {report.coverage.passed} · Deviations: {report.coverage.deviations} · Unknown: {report.coverage.unknown} · Unsupported declared schemes: {report.coverage.unsupportedDeclaredSchemes}.</p>
   <p>No customer runtime verification. Untested customer operations: {String(report.coverage.untestedCustomerOperations)}. Empty findings are not evidence of a safe customer API.</p>
   <label>Filter fixture evaluations<select value={filter} onChange={e=>setFilter(e.target.value)}><option value="ALL">All</option>{["PASS","DEVIATION","UNKNOWN","SKIPPED"].map(x=><option key={x}>{x}</option>)}</select></label>
   <table><thead><tr><th>Assertion</th><th>Identity</th><th>Expected</th><th>Observed</th><th>Outcome</th></tr></thead>
    <tbody>{shown.map(x=><tr key={x.id}><td>{x.ruleId}</td><td>{x.identity}</td><td>{x.expected}</td><td>{x.observed} ({x.status})</td><td>{x.result}</td></tr>)}</tbody></table>
   {shown.length===0&&<p>No evaluations for the selected filter.</p>}
   <h3>Evidence-backed fixture observations</h3>
   {findings.length===0&&<p>No deviations in this fixture. Customer API safety remains UNKNOWN.</p>}
   {findings.map(f=><article className="finding" key={f.id}><strong>{f.ruleId}</strong><p>{f.explanation}</p><p>{f.remediation}</p>
    <button className="secondary" onClick={()=>void evidence(f.evidenceId)}>Inspect redacted fixture evidence</button></article>)}
   {detail&&<section><h4>Redacted evidence detail</h4><pre>{JSON.stringify(detail,null,2)}</pre></section>}
   <h3>Coverage limitations</h3><ul>{report.limitations.map(x=><li key={x}>{x}</li>)}</ul>
  </>}
 </section>;
}
