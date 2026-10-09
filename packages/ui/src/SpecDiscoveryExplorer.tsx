import React,{useEffect,useState} from "react";
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
async function api<T>(token:string,path:string,method="GET",data?:unknown,extra?:Record<string,string>):Promise<T>{
 const response=await fetch(BASE+path,{method,headers:{authorization:"Bearer "+token,"content-type":"application/json",...extra},body:data===undefined?undefined:JSON.stringify(data)});
 const payload=await response.json() as T&{error?:string;requestId?:string};
 if(!response.ok && !(response.status===422 && (payload as {status?:string}).status==="FAILED"))throw new Error((payload.error??"REQUEST_FAILED")+" ("+response.status+")"+(payload.requestId?" · "+payload.requestId:""));
 return payload;
}
type Version={specificationId:string;version:number;format:string;rawFingerprint:string;normalizedFingerprint:string;selected:boolean;assessmentEligible:boolean;coverage:string;importedAt:string};
type ImportState={id:string;status:string;errorCode?:string;format?:string;version?:number;specificationId?:string;deduplicated?:boolean;assessmentEligible?:boolean};
type Auth={state:string;source:string;requirements:Record<string,string[]>[]};
type Param={name:string;in:string;required:boolean;type:string|null;format:string|null;pointer:string;constraints:Record<string,unknown>};
type Shape={mediaType:string;status:string|null;schemaFingerprint:string|null;type:string|null;requiredProperties:string[];nullable:boolean;composition:string[];pointer:string};
type Operation={key:string;method:string;path:string;summary:string|null;description:string|null;tags:string[];folder:string[];deprecated:boolean;pointer:string;servers:string[];auth:Auth;parameters:Param[];requestBodies:Shape[];responses:Shape[];warnings:string[];unresolved:string[]};
type Detail={metadata:{title:string|null;declaredVersion:string|null;servers:string[];warnings:string[];coverage:string};schemes:Record<string,{type:string;flows?:string[]}>;format:string;assessmentEligible:boolean};
type Diff={added:string[];removed:string[];changed:{key:string;fields:string[];possibleBreaking:boolean;fromPointer:string;toPointer:string}[];metadataChanges:string[]};
export function SpecDiscoveryExplorer({token,targetId,onSelected,active}:{token:string;targetId:string;onSelected:(spec:string)=>Promise<void>;active:boolean}){
 const [versions,setVersions]=useState<Version[]>([]),[imports,setImports]=useState<ImportState[]>([]);
 const [selected,setSelected]=useState(""),[operations,setOperations]=useState<Operation[]>([]);
 const [detail,setDetail]=useState<Detail|null>(null),[current,setCurrent]=useState<Operation|null>(null);
 const [error,setError]=useState(""),[info,setInfo]=useState(""),[busy,setBusy]=useState(false),[loading,setLoading]=useState(true);
 const [search,setSearch]=useState(""),[method,setMethod]=useState(""),[auth,setAuth]=useState(""),[tag,setTag]=useState("");
 const [offset,setOffset]=useState(0),[from,setFrom]=useState(""),[to,setTo]=useState(""),[diff,setDiff]=useState<Diff|null>(null);
 const [showSources,setShowSources]=useState(false);
 const version=versions.find(x=>x.specificationId===selected);
 async function refresh(){
  if(!targetId)return;
  const [v,jobs]=await Promise.all([
   api<Version[]>(token,"/v2/targets/"+targetId+"/specifications?limit=100"),
   api<ImportState[]>(token,"/v2/targets/"+targetId+"/specifications/imports?limit=20")
  ]);
  setVersions(v);setImports(jobs);
  setSelected(previous=>v.some(x=>x.specificationId===previous)?previous:(v[0]?.specificationId??""));
  setFrom(v[1]?.specificationId??"");
  setTo(v[0]?.specificationId??"");
 }
 useEffect(()=>{let live=true;setSelected("");setCurrent(null);setDiff(null);setError("");setLoading(true);
  void refresh().catch(e=>{if(live)setError(String(e));}).finally(()=>{if(live)setLoading(false);});
  return()=>{live=false;};
 },[targetId,token]);
 useEffect(()=>{let live=true;setCurrent(null);setDetail(null);setOperations([]);
  if(selected){
   const q=new URLSearchParams({limit:"40",offset:String(offset)});if(search)q.set("search",search);if(method)q.set("method",method);if(auth)q.set("auth",auth);if(tag)q.set("tag",tag);
   void Promise.all([api<Operation[]>(token,"/v2/specifications/"+selected+"/operations?"+q),api<Detail>(token,"/v2/specifications/"+selected)])
    .then(([ops,meta])=>{if(live){setOperations(ops);setDetail(meta);}}).catch(e=>{if(live)setError(String(e));});
  }return()=>{live=false;};
 },[token,selected,offset,search,method,auth,tag]);
 const attempt=async(fn:()=>Promise<void>)=>{setBusy(true);setError("");setInfo("");try{await fn();}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}};
 async function upload(e:React.ChangeEvent<HTMLInputElement>){
  const file=e.target.files?.[0];if(!file)return;
  await attempt(async()=>{
   if(file.size>1048576)throw new Error("DOCUMENT_SIZE_LIMIT");
   const payload=await api<ImportState>(token,"/v2/targets/"+targetId+"/specifications/imports","POST",{filename:file.name,content:await file.text()},{"idempotency-key":"import-"+crypto.randomUUID()});
   await refresh();
   if(payload.status!=="COMPLETED")throw new Error("Import "+payload.status+": "+(payload.errorCode??"VALIDATION_FAILED"));
   setSelected(payload.specificationId??"");
   setInfo("Imported "+payload.format+" v"+payload.version+(payload.deduplicated?" · deduplicated":"")+". Declarations only; no live endpoints contacted.");
   if(payload.specificationId&&("assessmentEligible" in payload)&&payload.assessmentEligible===true)await onSelected(payload.specificationId);
  });
  e.target.value="";
 }
 async function selectVersion(spec:string){
  const previous=versions.find(v=>v.selected)?.specificationId??null;
  await attempt(async()=>{
   await api(token,"/v2/targets/"+targetId+"/specifications/"+spec+"/select","POST",{expectedSelectedId:previous});
   await refresh();await onSelected(spec);
   setInfo("Version selected for existing SPEC_ONLY assessment pipeline. Authorized network requests: 0.");
  });
 }
 async function compare(){
  if(!from||!to||from===to)return;
  await attempt(async()=>{
   const result=await api<Diff>(token,"/v2/targets/"+targetId+"/specifications/compare","POST",{fromSpecificationId:from,toSpecificationId:to});
   setDiff(result);
  });
 }
 async function openOperation(key:string){
  await attempt(async()=>{
   const op=await api<Operation>(token,"/v2/specifications/"+selected+"/operations/"+encodeURIComponent(key));
   setCurrent(op);setShowSources(true);
  });
 }
 return <section aria-label="API specification discovery" className="discovery">
  <h2>API specification & offline discovery · Phase 2</h2>
  <p>Specification-derived inventory only. <strong>No live endpoint discovery, scanning, network permits or runtime-confirmed vulnerabilities.</strong></p>
  {error&&<p role="alert" className="error">{error}</p>}
  {info&&<p role="status">{info}</p>}
  <h3>Import supported API descriptions</h3>
  <label htmlFor="discovery-file">OpenAPI 3.0 / 3.1, Swagger 2.0 JSON/YAML or Postman Collection v2.1 JSON (≤1 MiB)</label>
  <input id="discovery-file" type="file" accept=".json,.yaml,.yml" disabled={busy||!active} onChange={e=>void upload(e)}/>
  {loading?<p role="status">Loading persisted specification versions…</p>:
    versions.length===0?<p>No imported discovery versions yet. Historical Phase 0 specifications remain in the original Assessment section.</p>:null}
  <h3>Import jobs</h3>
  <table><thead><tr><th>State</th><th>Format</th><th>Safe diagnostic</th></tr></thead><tbody>{imports.map(job=><tr key={job.id}><td>{job.status}</td><td>{job.format??"—"}</td><td>{job.errorCode??"—"}</td></tr>)}</tbody></table>
  <h3>Specification version history</h3>
  <table><thead><tr><th>Version</th><th>Format</th><th>Coverage</th><th>Assessment</th><th>Explore</th></tr></thead><tbody>{versions.map(v=><tr key={v.specificationId}>
   <td>v{v.version} {v.selected?"(selected)":""}</td><td>{v.format}</td><td>{v.coverage}</td>
   <td>{v.assessmentEligible?<button className="secondary" disabled={busy||v.selected||!active} onClick={()=>void selectVersion(v.specificationId)}>{v.selected?"Selected":"Select for SPEC_ONLY"}</button>:<span>Ineligible: legacy rules do not support this format</span>}</td>
   <td><button className="secondary" onClick={()=>{setSelected(v.specificationId);setOffset(0);}} disabled={busy}>Explore v{v.version}</button></td>
  </tr>)}</tbody></table>
  {version&&<><h3>Normalized inventory explorer · v{version.version}</h3>
    <p>Format: {version.format} · raw SHA-256: <code>{version.rawFingerprint.slice(0,20)}</code>… · normalized: <code>{version.normalizedFingerprint.slice(0,20)}</code>…</p>
    <p>Coverage: {version.coverage} · {version.assessmentEligible?"Eligible for deterministic SPEC_ONLY assessment":"Inspection/diff only; legacy assessment translation not verified"}.</p>
    {detail&&<><p>Declared API: {detail.metadata.title??"Untitled"} · declared servers: {detail.metadata.servers.length}</p>
      <p>Security scheme inventory: {Object.keys(detail.schemes).length} · {Object.entries(detail.schemes).map(([k,v])=>k+" ("+v.type+")").join(", ")||"None declared"}</p>
      {detail.metadata.warnings.length>0&&<details><summary>Import coverage warnings ({detail.metadata.warnings.length})</summary><ul>{detail.metadata.warnings.map((w,i)=><li key={i}>{w}</li>)}</ul></details>}
    </>}
    <div className="formgrid">
     <label>Search method/path<input value={search} onChange={e=>{setSearch(e.target.value);setOffset(0);}} placeholder="/v1/users"/></label>
     <label>Method<select value={method} onChange={e=>{setMethod(e.target.value);setOffset(0);}}><option value="">All methods</option>{["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","TRACE"].map(x=><option key={x}>{x}</option>)}</select></label>
     <label>Declared auth<select value={auth} onChange={e=>{setAuth(e.target.value);setOffset(0);}}><option value="">Any auth declaration</option>{["DECLARED","INHERITED","OVERRIDDEN","EXPLICIT_NONE","UNDECLARED","UNKNOWN"].map(x=><option key={x}>{x}</option>)}</select></label>
     <label>Tag<input value={tag} onChange={e=>{setTag(e.target.value);setOffset(0);}} placeholder="payments"/></label>
    </div>
    <table><thead><tr><th>Operation</th><th>Declared auth</th><th>Provenance</th><th>Details</th></tr></thead><tbody>{operations.map(op=><tr key={op.key}><td><strong>{op.method}</strong> <code>{op.path}</code> {op.deprecated?"(deprecated)":""}</td><td>{op.auth.state}</td><td><code>{op.pointer}</code></td><td><button className="secondary" onClick={()=>void openOperation(op.key)}>Inspect operation</button></td></tr>)}</tbody></table>
    {operations.length===0&&<p>No operations match these filters.</p>}
    <button className="secondary" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-40))}>Previous operations</button>
    <button className="secondary" disabled={operations.length<40} onClick={()=>setOffset(offset+40)}>Next operations</button>
    {current&&<article className="finding"><h4>Operation details · {current.method} {current.path}</h4>
     <p>{current.summary} · {current.description} · folder: {current.folder.join(" / ")||"Root"}</p>
     <p>Effective auth: <strong>{current.auth.state}</strong> · {JSON.stringify(current.auth.requirements)}</p>
     <h5>Declared parameters</h5>
     <table><thead><tr><th>Location</th><th>Name</th><th>Required</th><th>Type</th></tr></thead><tbody>{current.parameters.map((p,i)=><tr key={i}><td>{p.in}</td><td>{p.name}</td><td>{String(p.required)}</td><td>{p.type??"unknown"}</td></tr>)}</tbody></table>
     <h5>Request body shape</h5>
     <ul>{current.requestBodies.map((x,i)=><li key={i}>{x.mediaType} · type {x.type??"unknown"} · required {x.requiredProperties.join(", ")||"none declared"}</li>)}</ul>
     <h5>Declared responses</h5>
     <ul>{current.responses.map((x,i)=><li key={i}>{x.status??"unknown"} · {x.mediaType} · type {x.type??"unknown"} · nullable {String(x.nullable)}</li>)}</ul>
     <p>Unresolved variables: {current.unresolved.join(", ")||"None reported"} · warnings: {current.warnings.join(", ")||"None"}</p>
     <button className="secondary" onClick={()=>setShowSources(!showSources)}>{showSources?"Hide":"Show"} source pointers</button>
     {showSources&&<pre className="source-pointers">{[current.pointer,...current.parameters.map(p=>p.pointer),...current.requestBodies.map(x=>x.pointer),...current.responses.map(x=>x.pointer)].join("\n")}</pre>}
    </article>}
  </>}
  <h3>Structural version comparison</h3>
  <div className="formgrid"><label>From version<select value={from} onChange={e=>setFrom(e.target.value)}><option value="">Select baseline</option>{versions.map(v=><option key={v.specificationId} value={v.specificationId}>v{v.version} · {v.format}</option>)}</select></label>
   <label>To version<select value={to} onChange={e=>setTo(e.target.value)}><option value="">Select changed version</option>{versions.map(v=><option key={v.specificationId} value={v.specificationId}>v{v.version} · {v.format}</option>)}</select></label></div>
  <button disabled={!from||!to||from===to||busy} onClick={()=>void compare()}>Compare structural versions</button>
  {diff&&<article className="finding"><h4>Structural diff — review required</h4>
    <p><strong>{diff.added.length}</strong> added · <strong>{diff.removed.length}</strong> removed · <strong>{diff.changed.length}</strong> changed operations</p>
    <p>These are structural declarations, not confirmed runtime breaking behavior.</p>
    <h5>Added</h5><ul>{diff.added.map(k=><li key={k}>{k}</li>)}</ul>
    <h5>Removed</h5><ul>{diff.removed.map(k=><li key={k}>{k}</li>)}</ul>
    <h5>Changed</h5><ul>{diff.changed.map(c=><li key={c.key}>{c.key}: {c.fields.join(", ")} {c.possibleBreaking?"· possible breaking change candidate":""}</li>)}</ul>
    <p>Other metadata changes: {diff.metadataChanges.join(", ")||"None"}</p>
  </article>}
 </section>;
}
