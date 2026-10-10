/** Isolated GH Actions dev-tool advisory triage. Never suppress production audit. */
import {readFileSync} from "node:fs";
import {spawnSync} from "node:child_process";
if(process.env.GITHUB_ACTIONS!=="true")throw Error("GITHUB_HOSTED_AUDIT_REQUIRED");
const lock=JSON.parse(readFileSync("package-lock.json","utf8"));
const pkg=JSON.parse(readFileSync("package.json","utf8"));
const run=spawnSync("npm",["audit","--json","--include=dev"],{
 encoding:"utf8",timeout:100000,maxBuffer:18*1024*1024});
if(run.error||run.signal)throw Error("DEV_ADVISORY_QUERY_UNAVAILABLE");
let report;
try{report=JSON.parse(run.stdout??"");}catch{throw Error("DEV_ADVISORY_INVALID_JSON");}
if(report.error)throw Error("DEV_ADVISORY_PROVIDER_ERROR_"+String(report.error.code??"UNKNOWN"));
const scripts=Object.values(pkg.scripts??{}).map(String).join(" ");
const rows=Object.entries(report.vulnerabilities??{}).map(([name,issue])=>{
 const data=issue&&typeof issue==="object"?issue:{};
 const versions=Object.entries(lock.packages??{}).filter(([path])=>
  path.endsWith("/node_modules/"+name)||path==="node_modules/"+name);
 const actual=versions.map(([,info])=>info.version).filter(Boolean);
 const devOnly=versions.length>0&&versions.every(([,info])=>info.dev===true);
 const directDev=Object.hasOwn(pkg.devDependencies??{},name);
 const scriptInvoked=scripts.includes(name);
 return {name,versions:[...new Set(actual)],severity:data.severity??"UNKNOWN",
  directDev,devOnlyInLock:devOnly,scriptInvoked,
  review:!devOnly?"POTENTIALLY_PRODUCTION_REACHABLE":
    scriptInvoked?"CI_OR_BUILD_EXECUTABLE":"DEV_DEPENDENCY_TRANSITIVE_REVIEW",
  fixAvailable:data.fixAvailable??null};
});
console.log("PHASE14_DEV_ADVISORY_TRIAGE "+JSON.stringify({
 total:rows.length,bySeverity:report.metadata?.vulnerabilities??{},
 productionScanner:"SEPARATE_STRICT_GATE",items:rows.slice(0,100),
 note:"Development tool advisories can affect trusted CI/build operations; do not infer safety solely from dev=true."}));
if(rows.some(x=>["high","critical"].includes(x.severity)&&
 (!x.devOnlyInLock||x.scriptInvoked))){
 console.error("PHASE14_UNMITIGATED_EXECUTED_OR_PRODUCTION_REACHABLE_DEV_ADVISORY");
 process.exitCode=1;
}
