import React,{useEffect,useState} from "react";
type Target={id:string;name:string;base_url:string;environment:string;revision:number;verification_version:number;scope_revision:number;lifecycle:string;ownership_status:string};
type Scope={id:string;revision:number;proposal:{origins:string[];paths:string[];exclusions:string[];methods:string[];maxRequests:number;operations:string[];windowStart:string|null;windowEnd:string|null};authorityStatus:string};
type Challenge={id:string;status:string;expiresAt:string};
type Credential={id:string;reference:string;status:string};
type History={id:string;action:string;revision:number;occurredAt:string};
type VerificationDecision={id:string;decision:string;authority:string;decidedAt:string;verificationVersion:number};
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
async function api<T>(token:string,path:string,method="GET",body?:unknown):Promise<T>{
 const r=await fetch(BASE+path,{method,headers:{authorization:"Bearer "+token,"content-type":"application/json"},body:body===undefined?undefined:JSON.stringify(body)});
 const payload=await r.json() as T&{error?:string;requestId?:string};
 if(!r.ok)throw new Error(payload.error+" ("+r.status+")"+(payload.requestId?" · "+payload.requestId:""));
 return payload;
}
export function TargetOnboarding({token,targetId,onChanged}:{token:string;targetId:string;onChanged:()=>Promise<void>}){
 const [target,setTarget]=useState<Target|null>(null);
 const [scopes,setScopes]=useState<Scope[]>([]);
 const [challenges,setChallenges]=useState<Challenge[]>([]);
 const [history,setHistory]=useState<History[]>([]);
 const [decisions,setDecisions]=useState<VerificationDecision[]>([]);
 const [credentials,setCredentials]=useState<Credential[]>([]);
 const [name,setName]=useState("");
 const [url,setUrl]=useState("");
 const [environment,setEnvironment]=useState("SYNTHETIC");
 const [paths,setPaths]=useState("/");
 const [exclusions,setExclusions]=useState("/admin");
 const [methods,setMethods]=useState("GET,HEAD");
 const [operations,setOperations]=useState("");
 const [windowStart,setWindowStart]=useState("");
 const [windowEnd,setWindowEnd]=useState("");
 const [maxRequests,setMaxRequests]=useState("0");
 const [credential,setCredential]=useState("");
 const [attestation,setAttestation]=useState("");
 const [claim,setClaim]=useState("");
 const [selectedChallenge,setSelectedChallenge]=useState("");
 const [status,setStatus]=useState("");
 const [err,setErr]=useState("");
 const [busy,setBusy]=useState(false);
 const [showHistory,setShowHistory]=useState(false);
 async function refresh() {
  if(!targetId)return;
  const [t,s,c,h,refs,v]=await Promise.all([
    api<Target>(token,"/v1/targets/"+targetId),
    api<Scope[]>(token,"/v1/targets/"+targetId+"/scopes"),
    api<Challenge[]>(token,"/v1/targets/"+targetId+"/verification/challenges"),
    api<History[]>(token,"/v1/targets/"+targetId+"/history"),
    api<Credential[]>(token,"/v1/targets/"+targetId+"/credentials"),
    api<VerificationDecision[]>(token,"/v1/targets/"+targetId+"/verification/decisions")
  ]);
  setTarget(t);setName(t.name);setUrl(t.base_url);setEnvironment(t.environment);
  setScopes(s);setChallenges(c);setHistory(h);setCredentials(refs);setDecisions(v);
  if(s[0]){setPaths(s[0].proposal.paths.join("\n"));setExclusions(s[0].proposal.exclusions.join("\n"));setMethods(s[0].proposal.methods.join(","));setMaxRequests(String(s[0].proposal.maxRequests));setOperations((s[0].proposal.operations??[]).join("\n"));setWindowStart(s[0].proposal.windowStart??"");setWindowEnd(s[0].proposal.windowEnd??"");}
 }
 useEffect(()=>{setTarget(null);setErr("");setStatus("");setAttestation("");setSelectedChallenge("");void refresh().catch(e=>setErr(String(e)));},[token,targetId]);
 async function run(fn:()=>Promise<unknown>){setBusy(true);setErr("");setStatus("");try{await fn();await refresh();await onChanged();}catch(e){setErr(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
 async function update(e:React.FormEvent){e.preventDefault();if(!target)return;await run(async()=>{
  const changed=await api<Target>(token,"/v1/targets/"+targetId,"PATCH",{revision:target.revision,name,baseUrl:url,environment});
  setStatus("Target revision "+changed.revision+" saved. Scope/verification invalidated if origin or environment changed.");
 });}
 async function scope(e:React.FormEvent){e.preventDefault();if(!target)return;await run(async()=>{
  const split=(v:string)=>v.split(/[\n,]+/).map(x=>x.trim()).filter(Boolean);
  const origin=new URL(target.base_url).origin;
  const r=await api<{scopeRevision:number}>(token,"/v1/targets/"+targetId+"/scopes","POST",
   {revision:target.revision,proposal:{origins:[origin],paths:split(paths),exclusions:split(exclusions),
   methods:split(methods),operations:split(operations),maxRequests:Number(maxRequests),windowStart:windowStart||null,windowEnd:windowEnd||null}});
  setStatus("Scope proposal revision "+r.scopeRevision+" persisted. Host approval NOT granted.");
 });}
 async function issue(){if(!target)return;await run(async()=>{
  const issued=await api<{id:string;expiresAt:string}>(token,"/v1/targets/"+targetId+"/verification/challenges","POST",{revision:target.revision});
  setSelectedChallenge(issued.id);setAttestation("");setStatus("Challenge issued until "+issued.expiresAt+". Pending Host verification.");
 });}
 async function synthetic(){if(!selectedChallenge)return;await run(async()=>{
  const response=await api<{attestation:string}>(token,"/v1/test-authority/attest","POST",{targetId,challengeId:selectedChallenge});
  setAttestation(response.attestation);setStatus("Test-only attestation issued. Never production Host proof.");
 });}
 async function submit(e:React.FormEvent){e.preventDefault();if(!selectedChallenge)return;await run(async()=>{
  const response=await api<{status:string}>(token,"/v1/targets/"+targetId+"/verification/evidence","POST",
    {challengeId:selectedChallenge,evidenceType:"SIGNED_SYNTHETIC_ATTESTATION",attestation});
  setStatus("Verification result: "+response.status+" · NOT Host verified");setAttestation("");
 });}
 async function submitClaim(){if(!selectedChallenge)return;await run(async()=>{
  const response=await api<{status:string}>(token,"/v1/targets/"+targetId+"/verification/evidence","POST",
    {challengeId:selectedChallenge,evidenceType:"CUSTOMER_CLAIM",attestation:claim});
  setStatus("Untrusted customer claim recorded: "+response.status+". No ownership granted.");setClaim("");
 });}
 async function revokeVerification(){if(!target)return;await run(async()=>{
  await api(token,"/v1/targets/"+targetId+"/verification/revoke","POST",{revision:target.revision});
  setAttestation("");setStatus("All verification invalidated.");
 });}
 async function lifecycle(action:"SUSPEND"|"REVOKE"|"ARCHIVE"|"RESTORE"){if(!target)return;await run(async()=>{
  await api(token,"/v1/targets/"+targetId+"/lifecycle","POST",{revision:target.revision,action});
  setAttestation("");setStatus("Target lifecycle: "+action);
 });}
 async function addCredential(e:React.FormEvent){e.preventDefault();if(!target)return;await run(async()=>{
  await api(token,"/v1/targets/"+targetId+"/credentials","POST",{revision:target.revision,reference:credential});
  setCredential("");setStatus("Opaque reference stored. Host retrieval NOT authorized.");
 });}
 async function deleteCredential(id:string){await run(async()=>{
  await api(token,"/v1/targets/"+targetId+"/credentials/"+id,"DELETE");setStatus("Reference deleted.");
 });}

 if(!target)return <section aria-label="Target onboarding"><h2>Secure target onboarding · Phase 1</h2>{err?<p role="alert" className="error">{err}</p>:<p role="status">Loading target details…</p>}</section>;
 const active=target.lifecycle==="ACTIVE";
 return <section aria-label="Target onboarding">
  <h2>Secure target onboarding · Phase 1</h2>
  <p><strong>Lifecycle:</strong> {target.lifecycle} · <strong>Ownership:</strong> {target.ownership_status.replaceAll("_"," ")} · revision {target.revision}</p>
  <p><strong>Authority:</strong> {target.ownership_status==="SYNTHETIC_VERIFIED_TEST_ONLY"?"Synthetic TEST ONLY":"Pending real Host verification"} · <strong>Live execution:</strong> NOT AUTHORIZED</p>
  <p>Registered target ≠ ownership verified. Customer-proposed scope ≠ Host-approved scope. SPEC_ONLY does not send network requests.</p>
  {err&&<p role="alert" className="error">{err}</p>}
  {status&&<p role="status">{status}</p>}
  <form onSubmit={e=>void update(e)}><h3>Edit target metadata</h3><div className="formgrid">
    <label>Target display name<input value={name} onChange={e=>setName(e.target.value)} maxLength={120} required disabled={!active}/></label>
    <label>Canonical target URL<input type="url" value={url} onChange={e=>setUrl(e.target.value)} required disabled={!active}/></label>
    <label>Target environment<select value={environment} onChange={e=>setEnvironment(e.target.value)} disabled={!active}><option value="SYNTHETIC">SYNTHETIC</option><option value="STAGING">STAGING</option><option value="PRODUCTION">PRODUCTION</option></select></label>
   </div><button disabled={!active||busy}>Save target revision</button></form>
  <form onSubmit={e=>void scope(e)}><h3>Scope proposal (not authorization)</h3>
   <p>Canonical origin: <code>{new URL(target.base_url).origin}</code> · current proposal revision: {target.scope_revision}</p>
   <div className="formgrid">
    <label>Scope paths<textarea value={paths} onChange={e=>setPaths(e.target.value)} rows={3} disabled={!active}/></label>
    <label>Path exclusions<textarea value={exclusions} onChange={e=>setExclusions(e.target.value)} rows={3} disabled={!active}/></label>
    <label>Proposed methods<input value={methods} onChange={e=>setMethods(e.target.value)} disabled={!active}/></label>
    <label>Proposed request budget<input type="number" value={maxRequests} onChange={e=>setMaxRequests(e.target.value)} min={0} max={100000} disabled={!active}/></label>
    <label>API operation restrictions (proposed only)<textarea value={operations} onChange={e=>setOperations(e.target.value)} rows={2} placeholder="GET /v1/users" disabled={!active}/></label>
    <label>Scope window start (UTC ISO)<input value={windowStart} onChange={e=>setWindowStart(e.target.value)} placeholder="2026-11-01T00:00:00Z" disabled={!active}/></label>
    <label>Scope window end (UTC ISO)<input value={windowEnd} onChange={e=>setWindowEnd(e.target.value)} placeholder="2026-11-02T00:00:00Z" disabled={!active}/></label>
   </div><button disabled={!active||busy} type="submit">Save scope proposal</button></form>
  <p>Scope history: {scopes.length} revision(s). <strong>Host-approved scope: NONE.</strong></p>
  {scopes.length>0&&<table><thead><tr><th>Scope revision</th><th>Paths / methods</th><th>Authority</th></tr></thead><tbody>
    {scopes.map(x=><tr key={x.id}><td>{x.revision}</td><td>{x.proposal.paths.join(", ")} · {x.proposal.methods.join(", ")}</td><td>{x.authorityStatus}</td></tr>)}
  </tbody></table>}
  <div><h3>Ownership challenge</h3><p>Challenge nonce and customer claims cannot approve ownership. Only a test-only signed fixture is independently verified here.</p>
    <button disabled={!active||busy} onClick={()=>void issue()}>Issue verification challenge</button>
    <label>Issued challenge<select value={selectedChallenge} onChange={e=>{setSelectedChallenge(e.target.value);setAttestation("");}}>
      <option value="">Select issued challenge</option>{challenges.filter(c=>c.status==="ISSUED").map(c=><option key={c.id} value={c.id}>{c.id.slice(0,12)} · expires {new Date(c.expiresAt).toLocaleTimeString()}</option>)}
    </select></label>
    <p>Challenge history: {challenges.map(c=>c.status+" ("+c.id.slice(0,8)+")").join(" · ")||"None"}</p>
    <p>Recorded decisions: {decisions.map(v=>v.decision+" / "+v.authority).join(" · ")||"No Host verification decisions"}</p>
    <button className="secondary" disabled={!active||busy||!selectedChallenge} onClick={()=>void synthetic()}>Generate synthetic TEST proof</button>
    <form onSubmit={e=>void submit(e)}><label>Signed test attestation<textarea value={attestation} onChange={e=>setAttestation(e.target.value)} rows={2} placeholder="Test-only proof" autoComplete="off"/></label>
     <button disabled={!active||busy||!attestation||!selectedChallenge}>Submit signed test verification</button></form>
    <label>Unverified customer evidence<input value={claim} onChange={e=>setClaim(e.target.value)} placeholder="Claimed DNS text / screenshot reference"/></label>
    <button className="secondary" disabled={!active||busy||!selectedChallenge||!claim} onClick={()=>void submitClaim()}>Submit claim without verification</button>
    <button className="secondary" disabled={busy} onClick={()=>void revokeVerification()}>Revoke verification status</button>
  </div>
  <form onSubmit={e=>void addCredential(e)}><h3>Opaque credential references</h3>
   <p>References only; no API keys, passwords, tokens or Host secret retrieval.</p>
   <label>Credential profile reference<input value={credential} onChange={e=>setCredential(e.target.value)} placeholder="credref:syntheticprofile01" autoComplete="off" disabled={!active}/></label>
   <button disabled={!active||busy||!credential}>Store unverified reference</button>
  </form>
  <ul>{credentials.map(ref=><li key={ref.id}>{ref.reference} · {ref.status}<button className="secondary" disabled={!active||busy} onClick={()=>void deleteCredential(ref.id)}>Remove</button></li>)}</ul>
  <h3>Target lifecycle controls</h3>
  <div className="controls">
    <button disabled={!active||busy} onClick={()=>void lifecycle("SUSPEND")}>Suspend target</button>
    <button disabled={target.lifecycle!=="SUSPENDED"||busy} onClick={()=>void lifecycle("RESTORE")}>Restore suspended target</button>
    <button disabled={!["ACTIVE","SUSPENDED"].includes(target.lifecycle)||busy} onClick={()=>void lifecycle("REVOKE")}>Revoke target</button>
    <button disabled={!["ACTIVE","SUSPENDED"].includes(target.lifecycle)||busy} onClick={()=>void lifecycle("ARCHIVE")}>Archive target</button>
  </div>
  <button className="secondary" onClick={()=>setShowHistory(!showHistory)}>{showHistory?"Hide":"View"} target audit history ({history.length})</button>
  {showHistory&&<table><thead><tr><th>Action</th><th>Revision</th><th>Date</th></tr></thead><tbody>{history.map(h=><tr key={h.id}><td>{h.action}</td><td>{h.revision}</td><td>{new Date(h.occurredAt).toLocaleString()}</td></tr>)}</tbody></table>}
 </section>;
}
