import React,{useEffect,useState} from "react";
import {Phase12ReportControls} from "./Phase12ReportControls.js";
const BASE=(typeof import.meta.env==="object"&&import.meta.env.VITE_API_BASE)||"http://127.0.0.1:3001";
const UUID_V12=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
function persistReport(id:string){
 if(typeof window==="undefined")return;
 const u=new URL(window.location.href);
 if(UUID_V12.test(id))u.searchParams.set("apiReport",id);
 else u.searchParams.delete("apiReport");
 window.history.replaceState(null,"",u.pathname+u.search+u.hash);
}
type Overview={targets:{lifecycle:string;count:number}[];specificationCount:number;
 assessments:{status:string;mode:string;engine_version:string;count:number}[];
 immutableCompositeReports:number;notice:string};
type Run={id:string;status:string;mode:string;engineVersion:string;createdAt:string;
 reportId:string|null;isAutonomousVapt:boolean};
type Finding={key:string;ruleId:string;source:string;impact:string;operationKey:string;
 explanation:string;remediation:string;evidenceFingerprint:string};
type Report={assessmentId:string;sourceFingerprint:string;mode:string;scope:{targetId:string};
 summary:{findingCount:number;offlineOnly:boolean};findings:Finding[];
 coverage:{importedOperations:number;offlineOperations:number;ptRulesExecuted:number;
 ptRulesSelected:number;ptEvaluationsExecuted:number;ptEvaluationsPlanned:number};
 limitations:string[];disclaimer:string;verifiedFixed:false};
async function read<T>(token:string,path:string):Promise<T>{
 const response=await fetch(BASE+path,{headers:{authorization:"Bearer "+token},cache:"no-store"});
 if(!response.ok){const b=await response.json() as {error?:string};throw new Error(b.error??"REQUEST_FAILED");}
 return response.json() as Promise<T>;
}
export function Phase12Workspace({token,targetId}:{token:string;targetId:string}){
 const [overview,setOverview]=useState<Overview|null>(null),[runs,setRuns]=useState<Run[]>([]);
 const [reportId,setReportId]=useState(""),[report,setReport]=useState<Report|null>(null);
 const [busy,setBusy]=useState(false),[error,setError]=useState("");
 const [aiMode,setAiMode]=useState("DISABLED");
 useEffect(()=>{let active=true;setOverview(null);setRuns([]);setReport(null);setReportId("");
  setError("");if(!token||!targetId)return()=>{active=false;};
  setBusy(true);
  Promise.all([read<Overview>(token,"/v12/overview?targetId="+encodeURIComponent(targetId)),
   read<Run[]>(token,"/v12/assessments?targetId="+encodeURIComponent(targetId)+"&limit=50"),
   read<{mode:string}>(token,"/v12/ai/capabilities")]).then(([o,r,a])=>{
    if(active){setOverview(o);setRuns(r);setAiMode(a.mode);
     const previous=typeof window==="undefined"?null:new URLSearchParams(window.location.search).get("apiReport");
     if(previous&&UUID_V12.test(previous)&&r.some(item=>item.id===previous&&item.reportId)){
      setReportId(previous);
     }else if(previous){persistReport("");}
    }
   }).catch(e=>{if(active)setError(e instanceof Error?e.message:"REQUEST_FAILED");})
   .finally(()=>{if(active)setBusy(false);});
  return()=>{active=false;};
 },[token,targetId]);
 useEffect(()=>{let active=true;setReport(null);if(!reportId)return()=>{active=false;};
  setBusy(true);
  read<Report>(token,"/v12/reports/"+encodeURIComponent(reportId)+"/presentation")
   .then(r=>{if(active){
    if(r.scope.targetId!==targetId){
      setReport(null);setReportId("");persistReport("");setError("SELECTED_REPORT_TARGET_MISMATCH");
    }else setReport(r);
   }})
   .catch(e=>{if(active)setError(e instanceof Error?e.message:"REPORT_NOT_AVAILABLE");})
   .finally(()=>{if(active)setBusy(false);});
  return()=>{active=false;};
 },[token,targetId,reportId]);
 const finished=runs.filter(r=>r.isAutonomousVapt&&r.status==="COMPLETED"&&r.reportId);
 const date=(v:string)=>new Intl.DateTimeFormat("en",{dateStyle:"medium",timeStyle:"short",timeZone:"UTC"}).format(new Date(v));
 function jsonExport(){
  if(!reportId||!token)return;
  // Request uses bearer authentication; do not put synthetic bearer values in URLs.
  void fetch(BASE+"/v12/reports/"+encodeURIComponent(reportId)+"/export.json",{
   headers:{authorization:"Bearer "+token},cache:"no-store"}).then(async response=>{
    if(!response.ok)throw new Error("EXPORT_ACCESS_DENIED");
    const blob=await response.blob();
    const url=URL.createObjectURL(blob);const a=document.createElement("a");
    a.href=url;a.download="lumicsec-api-presentation-"+reportId+".json";a.click();
    URL.revokeObjectURL(url);
  }).catch(e=>setError(e instanceof Error?e.message:"EXPORT_FAILED"));
 }
 function pdfExport(){
  if(!reportId||!token)return;
  void fetch(BASE+"/v12/reports/"+encodeURIComponent(reportId)+"/export.pdf",{
   headers:{authorization:"Bearer "+token},cache:"no-store"}).then(async response=>{
    if(!response.ok)throw new Error("PDF_EXPORT_DENIED");
    if(!response.headers.get("content-type")?.startsWith("application/pdf"))throw new Error("INVALID_PDF_RESPONSE");
    const blob=await response.blob();if(blob.size>4*1024*1024)throw new Error("PDF_TOO_LARGE");
    const url=URL.createObjectURL(blob);const a=document.createElement("a");
    a.href=url;a.download="lumicsec-api-presentation-"+reportId+".pdf";a.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }).catch(e=>setError(e instanceof Error?e.message:"PDF_EXPORT_FAILED"));
 }
 return <section id="phase12-workspace" aria-labelledby="phase12-heading">
  <h2 id="phase12-heading">Unified API security workspace — Phase 12</h2>
  <p>Read-only evidence and reporting over existing synthetic-only assessment engines. No customer production scanning or verified-fixed authority.</p>
  {busy&&<p role="status">Loading authorized evidence…</p>}
  {error&&<p role="alert" className="error">{error}</p>}
  {overview&&<div>
   <h3>Evidence-backed overview</h3>
   <p>{overview.specificationCount} imported specifications · {overview.immutableCompositeReports} immutable composite reports</p>
   <table><caption>Actual target lifecycles</caption><thead><tr><th scope="col">Lifecycle</th><th scope="col">Targets</th></tr></thead>
    <tbody>{overview.targets.map(t=><tr key={t.lifecycle}><th scope="row">{t.lifecycle}</th><td>{t.count}</td></tr>)}</tbody></table>
   <table><caption>Actual assessment status and engine</caption><thead><tr><th scope="col">Status</th><th scope="col">Mode</th><th scope="col">Engine</th><th scope="col">Count</th></tr></thead>
    <tbody>{overview.assessments.map((a,i)=><tr key={i}><th scope="row">{a.status}</th><td>{a.mode}</td><td>{a.engine_version}</td><td>{a.count}</td></tr>)}</tbody></table>
  </div>}
  <h3>Historical assessments</h3>
  <p>Past runs are retrieved from the authorized PostgreSQL tenant, not browser-generated results.</p>
  {runs.length===0?<p>No assessments for the selected target.</p>:
  <table><thead><tr><th scope="col">Run</th><th scope="col">Status</th><th scope="col">Mode</th><th scope="col">Created (UTC)</th></tr></thead><tbody>
   {runs.map(r=><tr key={r.id}><th scope="row"><code>{r.id.slice(0,12)}</code></th><td>{r.status}</td><td>{r.mode}</td><td>{date(r.createdAt)}</td></tr>)}
  </tbody></table>}
  <label htmlFor="v12-report">Select a completed immutable composite report</label>
  <select id="v12-report" value={reportId} onChange={e=>{setError("");setReportId(e.target.value);persistReport(e.target.value);}}>
   <option value="">Choose authorized report</option>
   {finished.map(r=><option key={r.id} value={r.id}>{r.id.slice(0,12)} · {r.mode}</option>)}
  </select>
  {report&&<div>
   <h3>Immutable report presentation</h3>
   <p>Mode: {report.mode} · Findings observed: {report.summary.findingCount}</p>
   <p>Source fingerprint <code>{report.sourceFingerprint}</code></p>
   <p>Operations analyzed: {report.coverage.offlineOperations}/{report.coverage.importedOperations}.
    Synthetic evaluations: {report.coverage.ptEvaluationsExecuted}/{report.coverage.ptEvaluationsPlanned}.</p>
   <h4>Correlated findings and remediation</h4>
   {report.findings.length===0&&<p>No observed findings. This does not establish security.</p>}
   {report.findings.map((f,i)=><article className="finding" key={f.key+"-"+i}>
    <strong>{f.ruleId}</strong> · {f.source} · {f.impact} · <code>{f.operationKey}</code>
    <p>{f.explanation}</p><p>Remediation guidance: {f.remediation}</p>
    <p>Redacted evidence fingerprint <code>{f.evidenceFingerprint}</code></p>
   </article>)}
   <h4>Limitations</h4><ul>{report.limitations.map((l,i)=><li key={i}>{l}</li>)}</ul>
   <button type="button" onClick={jsonExport}>Download authorized JSON presentation</button>
   <button type="button" onClick={pdfExport}>Download authorized PDF report</button>
   <Phase12ReportControls key={targetId+reportId+token} token={token} targetId={targetId} reportId={reportId} findings={report.findings}/>
  </div>}
  <h3>Optional read-only AI</h3><p role="status">{aiMode} — no model provider configured or invoked. The assistant cannot start scans or change security evidence.</p>
 </section>;
}
