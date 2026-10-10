/** Printable Phase12 document from an already tenant-authorized immutable report.
 * No network access or model/execution/tool authority. Browser is a renderer only. */
import {chromium} from "@playwright/test";
import {emitDiagnostic} from "../../contracts/src/operational-diagnostics-v14.js";
import {PtError} from "./pt.js";
import type {presentVaptReport} from "./phase12.js";
type Report=ReturnType<typeof presentVaptReport>;
export type ReportBrand={displayName:string;reportTitle:string;accentHex:string;version:number};
const DEFAULT:ReportBrand={displayName:"Organization",reportTitle:"API Security Evidence Report",
 accentHex:"#2457A7",version:0};
const escape=(value:unknown)=>String(value??"").replace(/[&<>"']/g,ch=>({
 "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
})[ch]??"");
const entry=(key:string,value:unknown)=>"<tr><th scope=\"row\">"+escape(key)+"</th><td>"+escape(value)+"</td></tr>";
const table=(title:string,rows:string[])=>"<section><h2>"+escape(title)+"</h2><table><tbody>"+rows.join("")+"</tbody></table></section>";
export function buildPhase12PdfHtml(report:Report,custom?:ReportBrand){
 const brand=custom??DEFAULT;
 if(report.schemaVersion!=="api-security-report-presentation-v1"||
  report.customerRuntimeVerified!==false||report.verifiedFixed!==false||
  report.syntheticOnly!==true||!/^[0-9a-f]{64}$/.test(report.sourceFingerprint))
  throw new PtError(409,"UNTRUSTED_REPORT_PRESENTATION");
 if(!/^#[0-9a-fA-F]{6}$/.test(brand.accentHex)||
  brand.displayName.length>100||brand.reportTitle.length>120)
  throw new PtError(400,"INVALID_BRANDING");
 const findings=report.findings.slice(0,1000).map((finding,index)=>[
  "<article class=\"finding\"><h3>Finding ",String(index+1),": ",escape(finding.ruleId),"</h3>",
  "<p><b>Source:</b> ",escape(finding.source)," · <b>Impact:</b> ",
  escape(finding.impact)," · <b>Confidence:</b> ",escape(finding.confidence),"</p>",
  "<p><b>Operation:</b> <code>",escape(finding.operationKey||"Document-wide"),"</code></p>",
  "<p><b>Observation:</b> ",escape(finding.explanation),"</p>",
  "<p><b>Remediation guidance:</b> ",escape(finding.remediation),"</p>",
  "<p class=\"fingerprint\"><b>Redacted evidence reference:</b> ",escape(finding.evidenceFingerprint),"</p>",
  "<p class=\"subtle\">A fix claim is not VERIFIED_FIXED. Source: ",escape(finding.key),"</p></article>"
 ].join("")).join("");
 const limitations=report.limitations.map(x=>"<li>"+escape(x)+"</li>").join("");
 const impact=new Map<string,number>();
 for(const finding of report.findings)impact.set(finding.impact,(impact.get(finding.impact)??0)+1);
 const impactRows=[...impact.entries()].sort((a,b)=>a[0].localeCompare(b[0])).map(([level,n])=>entry(level,n));
 const inventoryRows=report.inventory.operations.slice(0,250).map(op=>
  entry(op.method+" "+op.path,op.key));
 const componentRows=report.components.map(x=>entry(x.engine+" / "+(x.id??"UNKNOWN"),x.status));
 const stageRows=report.autonomous.stages.map(x=>entry(x.stageId,x.engine));
 const evidenceRows=report.findings.slice(0,250).map(f=>entry(f.ruleId+" / "+f.revision,
  f.evidenceFingerprint+" / "+f.source));
 const remediationRows=report.findings.slice(0,250).map(f=>entry(f.ruleId+
  " — "+(f.operationKey||"Operation unspecified"),f.remediation));
 const truncatedOperations=report.inventory.operations.length>250;
 const truncatedEvidence=report.findings.length>250;
 return `<!doctype html><html lang="en"><head><meta charset="UTF-8"/>
 <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; font-src 'none'; script-src 'none'"/>
 <title>${escape(brand.reportTitle)}</title><style>
 @page{size:A4;margin:16mm 14mm 21mm}
 html{font-family:"Noto Sans",Arial,sans-serif;color:#1e2632;font-size:10pt;line-height:1.48}
 body{margin:0} h1{font-size:22pt;margin:0 0 10pt;color:${brand.accentHex}}
 h2{font-size:13pt;color:${brand.accentHex};margin:18pt 0 8pt}
 h3{font-size:11pt;margin:0 0 6pt} p{margin:5pt 0 10pt}
 .subtle{font-size:9pt;color:#495568} .banner{padding:12pt;border:1pt solid #63738a;margin:12pt 0}
 .finding{padding:9pt 0;border-bottom:1pt solid #ced6e2;break-inside:avoid-page}
 code,.fingerprint{overflow-wrap:anywhere;word-break:break-word;font-family:monospace;font-size:9pt}
 td,th{border-bottom:1pt solid #ced6e2;padding:5pt;text-align:left;vertical-align:top}
 table{width:100%;border-collapse:collapse} th{width:45%;font-weight:600}
 section{break-inside:auto} li{margin:5pt 0;overflow-wrap:anywhere}
 .mandatory{border:2pt solid #44566e;padding:10pt;break-inside:avoid-page}
 </style></head><body>
 <header><p class="subtle">${escape(brand.displayName)} · Presentation schema version 1 · Branding version ${brand.version}</p>
 <h1>${escape(brand.reportTitle)}</h1>
 <p><b>Assessment:</b> <code>${escape(report.assessmentId)}</code></p>
 <p><b>Immutable source fingerprint:</b> <code>${escape(report.sourceFingerprint)}</code></p>
 <p><b>Source committed (UTC):</b> ${escape(report.sourceCreatedAt)}</p>
 <p class="banner">ISOLATED SYNTHETIC SECURITY EVIDENCE — NOT A LIVE CUSTOMER PENETRATION TEST.</p></header>
 ${table("1. Report identity and cover",[
  entry("Presentation contract",report.schemaVersion),
  entry("Source assessment",report.assessmentId),
  entry("Source fingerprint",report.sourceFingerprint)])}
 ${table("2. Scope and environment",[
  entry("Target identifier",report.scope.targetId),
  entry("Specification identifier",report.scope.specificationId),
  entry("Assessment mode",report.mode),
  entry("Execution engine",report.scope.engineVersion),
  entry("Customer runtime verified","NO")])}
 <section><h2>3. Assessment methodology</h2>
  <p>SPEC_ONLY is static specification observation, not customer network execution.
  GOVERNED_SYNTHETIC is isolated, signed-permit-controlled fixture execution, not a production pentest.
  Evidence is drawn from the committed Phase11 parent report.</p></section>
 ${table("4. Target and specification summary",[
  entry("Specification version",report.scope.specificationVersion),
  entry("Specification fingerprint",report.scope.specimenFingerprint),
  entry("Inventory fingerprint",report.scope.inventoryFingerprint),
  entry("Imported operations",report.coverage.importedOperations),
  entry("Offline analysis engine",report.scope.offlineEngine)])}
 ${table("5. Executive overview",[
  entry("Observed findings",report.summary.findingCount),
  entry("Real customer vulnerabilities confirmed",0),
  entry("Offline only",report.summary.offlineOnly?"YES":"NO"),
  entry("Full governed synthetic assessment completed",report.summary.fullAuthorizedSyntheticAssessment?"YES":"NO"),
  entry("Verified fixed","NO")])}
 ${table("6. Evidence classification",[
  entry("Offline observation",report.evidenceClassification.offline),
  entry("Fixture observation",report.evidenceClassification.runtime),
  entry("Customer runtime",report.evidenceClassification.realCustomerRuntime),
  entry("Canonical retest authority",report.evidenceClassification.fixedVerification)])}
 ${table("7. Actual finding impact categories",impactRows.length?impactRows:[
  entry("Observed findings","NONE — absence of findings is not proof of safety")])}
 <section><h2>8. Detailed evidence-backed findings</h2>
  ${findings||"<p>No findings were observed in this report. This does NOT imply the API is secure.</p>"}
 </section>
 ${table("9. Evidence-linked remediation recommendations",remediationRows.length?remediationRows:[
  entry("Current evidence","No observed finding to remediate. Review gaps and untested behavior")])}
 ${table("10. API inventory and operation coverage",[
  entry("Imported operations",report.coverage.importedOperations),
  entry("Offline operations analyzed",report.coverage.offlineOperations),
  entry("Supported synthetic fixture operations",report.inventory.supportedSyntheticOperations),
  entry("Synthetic PT evaluations",String(report.coverage.ptEvaluationsExecuted)+"/"+String(report.coverage.ptEvaluationsPlanned)),
  ...inventoryRows,
  ...(truncatedOperations?[entry("Display truncation","Only first 250 imported operations shown; source JSON export retains complete bounded projection")]:[])
 ])}
 ${table("11. Offline specification analysis",[
  entry("Offline engine",report.scope.offlineEngine),
  entry("Operations analyzed",report.offline.operationsAnalyzed),
  entry("Observation limitations",report.offline.warning)])}
 ${table("12. Governed synthetic PT result",[
  entry("Scope fixture identifier",report.scope.fixtureId||"NONE — offline only"),
  entry("Fixture version",report.scope.fixtureVersion??"NOT TESTED"),
  entry("Fixture profile",report.scope.fixtureProfile||"NOT TESTED"),
  entry("Selected rules",report.coverage.ptRulesSelected),
  entry("Executed rules",report.coverage.ptRulesExecuted),
  entry("Planned evaluations",report.syntheticPt.plannedEvaluations),
  entry("Executed evaluations",report.syntheticPt.executedEvaluations),
  entry("Secure-negative fixture checks",report.syntheticPt.secureNegativeChecks),
  entry("Synthetic observations",report.syntheticPt.syntheticObservations)])}
 ${table("13. Autonomous orchestration stage coverage",[
  entry("Required stages",report.autonomous.requiredStages),
  entry("Completed stages",report.autonomous.completedStages),
  entry("Unknown or unstarted outcomes",report.autonomous.unstartedOrUnknown?"YES":"NO"),
  ...stageRows,...componentRows])}
 ${table("14. Isolated synthetic authorization and governor",[
  entry("Scope revision",report.scope.scopeRevision),
  entry("Plan fingerprint",report.scope.planFingerprint),
  entry("Synthetic policy",report.scope.ptPolicy||"NO LIVE PT POLICY"),
  entry("Redacted signed permit fingerprint",report.scope.permitFingerprint||"NOT APPLICABLE"),
  entry("Customer network requests",report.customerNetworkRequests),
  entry("External Host approval","NOT INTEGRATED")])}
 ${table("15. Unknown and unsupported behavior",[
  entry("Real customer runtime assessment","NOT EXECUTED"),
  entry("Offline-only runtime unknown",report.coverage.notTested?"YES":"NO"),
  entry("Assessment with no runtime evidence","UNKNOWN, never SAFE")])}
 <section><h2>16. Assessment limitations and caveats</h2><ul>${limitations}</ul></section>
 ${table("17. Historical comparison and compatibility",[
  entry("Lineage predecessor",report.lineageParentId??"NONE"),
  entry("Historical difference","NOT COMPUTED IN INDIVIDUAL REPORT"),
  entry("Compatibility requirement","Use authorized paired report comparison before interpreting trends"),
  entry("No longer observed","NEVER VERIFIED_FIXED")])}
 ${table("18. Appendix of redacted evidence references",[
  ...evidenceRows,
  ...(truncatedEvidence?[entry("Display truncation","Only first 250 evidence references shown; use authorized JSON projection for additional records")]:[]),
  ...(evidenceRows.length===0?[entry("Observed evidence","NONE")]:[])
 ])}
 ${table("19. Presentation generation and provenance metadata",[
  entry("Source committed at UTC",report.sourceCreatedAt),
  entry("Immutable source fingerprint",report.sourceFingerprint),
  entry("Presentation schema",report.schemaVersion),
  entry("Branding version",brand.version),
  entry("Customer runtime verified",report.customerRuntimeVerified?"YES":"NO"),
  entry("Security verdict mutation","NONE — generation is presentation only")])}
 <section class="mandatory"><h2>20. Mandatory synthetic security disclaimer</h2>
 <p>${escape(report.disclaimer)}</p>
 <p>NO EVIDENCE != SAFE; UNKNOWN != SAFE; NO LONGER OBSERVED != VERIFIED_FIXED.</p>
 <p>PDF GENERATION != NEW ASSESSMENT. Only the future authorized Host RetestVerificationAuthority can establish VERIFIED_FIXED.</p>
 </section></body></html>`;
}
// Only independent GitHub Actions children may expose controlled renderer faults.
// Never expose this via Fastify, an HTTP endpoint, or production environment.
const phase14ChildFault=(mode:string)=>process.env.NODE_ENV==="test"&&
 process.env.SYNTHETIC_AUTH_ENABLED==="true"&&process.env.GITHUB_ACTIONS==="true"&&
 process.env.PHASE14_PDF_CHILD_FAULT===mode&&typeof process.send==="function";
async function phase14RendererBarrier(stage:string,pid:number|undefined):Promise<void>{
 await new Promise<void>((resolve,reject)=>{
  const timeout=setTimeout(()=>{cleanup();reject(Error("PHASE14_RENDERER_BARRIER_TIMEOUT"));},9000);
  const resumed=(message:unknown)=>{
   if(typeof message==="object"&&message!==null&&
     (message as {kind?:unknown}).kind==="PHASE14_CONTINUE"){
    cleanup();resolve();
   }
  };
  const cleanup=()=>{clearTimeout(timeout);process.off("message",resumed);};
  process.on("message",resumed);
  process.send?.({kind:stage,chromiumPid:pid});
 });
}
let running=0;
export async function renderPhase12Pdf(report:Report,branding?:ReportBrand):Promise<Buffer>{
 if(running>=2)throw new PtError(429,"PDF_GENERATION_CONCURRENCY_LIMIT");
 const html=buildPhase12PdfHtml(report,branding);
 if(Buffer.byteLength(html,"utf8")>1024*1024)throw new PtError(413,"PDF_SOURCE_LIMIT");
 running++;
 const started=process.hrtime.bigint();
 try{
  // GitHub-hosted deterministic executable-launch failure, never enabled in production.
  const unavailable=process.env.NODE_ENV==="test"&&process.env.SYNTHETIC_AUTH_ENABLED==="true"&&
    process.env.PHASE14_TEST_PDF_UNAVAILABLE==="true";
  const processFault=["before-page","mid-render","render-timeout"].some(phase14ChildFault);
  // Playwright's Browser does NOT expose a process handle. Only for real
  // GitHub-hosted fault drills launch a private BrowserServer OS child.
  const browserServer=processFault?await chromium.launchServer({headless:true,timeout:15000}):null;
  const browser=browserServer?await chromium.connect(browserServer.wsEndpoint()):
    await chromium.launch({headless:true,timeout:15000,
      ...(unavailable?{executablePath:"/phase14-disposable-ci-nonexistent-chromium"}:{})});
  try{
   if(phase14ChildFault("before-page"))
     await phase14RendererBarrier("PHASE14_BROWSER_LAUNCHED",browserServer?.process().pid);
   const context=await browser.newContext({javaScriptEnabled:false,acceptDownloads:false});
   try{
    await context.route("**/*",route=>route.abort("blockedbyclient"));
    const page=await context.newPage();
    await page.setContent(html,{waitUntil:"domcontentloaded",timeout:15000});
    const pending=page.pdf({format:"A4",printBackground:true,displayHeaderFooter:true,
     margin:{top:"16mm",bottom:"21mm",left:"14mm",right:"14mm"},
     headerTemplate:"<span></span>",
     footerTemplate:'<div style="font-family:Arial;font-size:8px;width:100%;color:#444;text-align:right;padding-right:16mm">Page <span class="pageNumber"></span> / <span class="totalPages"></span></div>',
    });
    // Attach a rejection handler *before* the child can kill the real browser.
    void pending.catch(()=>undefined);
    if(phase14ChildFault("mid-render"))
     await phase14RendererBarrier("PHASE14_RENDER_IN_FLIGHT",browserServer?.process().pid);
    let timeout:ReturnType<typeof setTimeout>|undefined;
    const deadline=new Promise<never>((_,reject)=>{
      timeout=setTimeout(()=>{
        if(browserServer)browserServer.process().kill("SIGKILL");
        else void browser.close().catch(()=>undefined);
        reject(new PtError(503,"PDF_RENDER_TIMEOUT"));
      },phase14ChildFault("render-timeout")?350:20000);
    });
    try{
      const bytes=await Promise.race(phase14ChildFault("render-timeout")?
        [deadline]:[pending,deadline]);
      // Always keep a real timer in the test-timeout mode as well.
      if(bytes.length>4*1024*1024)throw new PtError(413,"PDF_OUTPUT_LIMIT");
      if(bytes.subarray(0,5).toString()!=="%PDF-")throw new PtError(500,"INVALID_PDF_BYTES");
      emitDiagnostic({kind:"REPORT_RENDER",classification:"OK",statusCode:200,
        durationMs:Number(process.hrtime.bigint()-started)/1e6});
      return bytes;
    }finally{if(timeout)clearTimeout(timeout);}

   }finally{await context.close();}
  }finally{
    await browser.close().catch(()=>undefined);
    if(browserServer)await browserServer.close().catch(()=>undefined);
  }
 }catch(e){
  emitDiagnostic({kind:"REPORT_RENDER",classification:"INTERNAL",statusCode:503,
    durationMs:Number(process.hrtime.bigint()-started)/1e6});
  if(e instanceof PtError)throw e;
  throw new PtError(503,"PDF_RENDERER_UNAVAILABLE_OR_TIMED_OUT");
 }finally{running--;}
}
