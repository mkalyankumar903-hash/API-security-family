/** Printable Phase12 document from an already tenant-authorized immutable report.
 * No network access or model/execution/tool authority. Browser is a renderer only. */
import {chromium} from "@playwright/test";
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
 <header><p class="subtle">${escape(brand.displayName)} · Presentation version 1 · Branding version ${brand.version}</p>
 <h1>${escape(brand.reportTitle)}</h1>
 <p><b>Assessment:</b> <code>${escape(report.assessmentId)}</code></p>
 <p><b>Immutable source fingerprint:</b> <code>${escape(report.sourceFingerprint)}</code></p>
 <p><b>Source committed (UTC):</b> ${escape(report.sourceCreatedAt)}</p>
 <p class="banner">ISOLATED SYNTHETIC SECURITY EVIDENCE — NOT A LIVE CUSTOMER PENETRATION TEST.</p></header>
 ${table("1. Scope and environment",[
 entry("Target identifier",report.scope.targetId),
 entry("Specification identifier",report.scope.specificationId),
 entry("Specification version",report.scope.specificationVersion),
 entry("Mode",report.mode),
 entry("Engine",report.scope.engineVersion),
 entry("Imported specification fingerprint",report.scope.specimenFingerprint)])}
 ${table("2. Executive overview",[
 entry("Observed evidence-backed findings",report.summary.findingCount),
 entry("Production runtime confirmed vulnerabilities",0),
 entry("Offline only",report.summary.offlineOnly?"YES":"NO"),
 entry("Governed synthetic assessment completed",report.summary.fullAuthorizedSyntheticAssessment?"YES":"NO"),
 entry("Customer runtime verified","NO"),
 entry("Verified fixed","NO")])}
 <section><h2>3. Methodology and classification</h2>
 <p>Imported specification analysis is document-only. Governed PT uses isolated synthetic fixtures, and its observations cannot establish customer production vulnerabilities.</p>
 <p>No customer network requests are authorized by this report. Execution of a worker is not vulnerability verification.</p></section>
 ${table("4. Actual coverage and unknowns",[
 entry("Imported operations",report.coverage.importedOperations),
 entry("Offline operations analyzed",report.coverage.offlineOperations),
 entry("Selected synthetic PT rules",report.coverage.ptRulesSelected),
 entry("Executed synthetic PT rules",report.coverage.ptRulesExecuted),
 entry("Planned synthetic evaluations",report.coverage.ptEvaluationsPlanned),
 entry("Executed synthetic evaluations",report.coverage.ptEvaluationsExecuted),
 entry("Runtime assessments not performed",report.coverage.notTested?"YES":"NO")])}
 <section><h2>5. Evidence-backed findings and remediation</h2>
 ${findings||"<p>No findings were observed in this report. This does NOT imply the API is secure.</p>"}
 </section>
 <section><h2>6. Limitations and unsupported evidence</h2><ul>${limitations}</ul></section>
 <section class="mandatory"><h2>Mandatory synthetic security disclaimer</h2>
 <p>${escape(report.disclaimer)}</p>
 <p>NO EVIDENCE != SAFE; UNKNOWN != SAFE; NO LONGER OBSERVED != VERIFIED_FIXED.</p>
 <p>PDF GENERATION != NEW ASSESSMENT. Only the future authorized Host RetestVerificationAuthority can establish VERIFIED_FIXED.</p>
 </section></body></html>`;
}
let running=0;
export async function renderPhase12Pdf(report:Report,branding?:ReportBrand):Promise<Buffer>{
 if(running>=2)throw new PtError(429,"PDF_GENERATION_CONCURRENCY_LIMIT");
 const html=buildPhase12PdfHtml(report,branding);
 if(Buffer.byteLength(html,"utf8")>1024*1024)throw new PtError(413,"PDF_SOURCE_LIMIT");
 running++;
 try{
  const browser=await chromium.launch({headless:true,timeout:15000});
  try{
   const context=await browser.newContext({javaScriptEnabled:false,acceptDownloads:false});
   try{
    await context.route("**/*",route=>route.abort("blockedbyclient"));
    const page=await context.newPage();
    await page.setContent(html,{waitUntil:"domcontentloaded",timeout:15000});
    const bytes=await page.pdf({format:"A4",printBackground:true,displayHeaderFooter:true,
     margin:{top:"16mm",bottom:"21mm",left:"14mm",right:"14mm"},
     headerTemplate:"<span></span>",
     footerTemplate:'<div style="font-family:Arial;font-size:8px;width:100%;color:#444;text-align:right;padding-right:16mm">Page <span class="pageNumber"></span> / <span class="totalPages"></span></div>',
     timeout:15000});
    if(bytes.length>4*1024*1024)throw new PtError(413,"PDF_OUTPUT_LIMIT");
    if(bytes.subarray(0,5).toString()!=="%PDF-")throw new PtError(500,"INVALID_PDF_BYTES");
    return bytes;
   }finally{await context.close();}
  }finally{await browser.close();}
 }catch(e){
  if(e instanceof PtError)throw e;
  throw new PtError(503,"PDF_RENDERER_UNAVAILABLE_OR_TIMED_OUT");
 }finally{running--;}
}
