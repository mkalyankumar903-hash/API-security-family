/** Frozen dependency and advisory evidence. GitHub-hosted synthetic only; never publishes packages. */
import {readFileSync} from "node:fs";
import {spawnSync} from "node:child_process";
const lock=JSON.parse(readFileSync("package-lock.json","utf8"));
if(lock.lockfileVersion!==3||typeof lock.packages!=="object")throw Error("LOCKFILE_V3_REQUIRED");
let remote=0,local=0;const issues=[];
for(const [path,item] of Object.entries(lock.packages)){
 if(!path||!path.includes("node_modules/"))continue;
 if(!item||typeof item!=="object"){issues.push(path+":INVALID_RECORD");continue;}
 if(item.link===true){local++;continue;}
 if(typeof item.version!=="string"){issues.push(path+":MISSING_VERSION");continue;}
 if(!item.integrity||!/^sha512-[A-Za-z0-9+/=]+$/.test(item.integrity)){
  issues.push(path+":MISSING_SHA512_INTEGRITY");continue;
 }
 if(typeof item.resolved!=="string"||!item.resolved.startsWith("https://")){
  issues.push(path+":NON_HTTPS_TARBALL");continue;
 }
 remote++;
}
console.log("PHASE14_LOCKFILE "+JSON.stringify({version:lock.lockfileVersion,remoteIntegrityVerified:remote,
 linkedWorkspacePackages:local,invariantViolations:issues.length,exampleViolations:issues.slice(0,10)}));
if(issues.length)process.exitCode=1;
const run=spawnSync("npm",["audit","--json","--omit=dev"],{
 encoding:"utf8",timeout:90000,maxBuffer:16*1024*1024,env:{...process.env,npm_config_audit:"true"}
});
if(run.error||run.signal){console.error("PHASE14_ADVISORY_QUERY_FAILED "+(run.error?.name??"UNKNOWN"));process.exitCode=1;}
else {
 let audit;
 try{audit=JSON.parse(run.stdout??"");}catch{console.error("PHASE14_ADVISORY_INVALID_JSON");process.exitCode=1;}
 if(audit){
  if(audit.error){console.error("PHASE14_ADVISORY_SERVICE_UNAVAILABLE "+String(audit.error.code??"UNKNOWN"));process.exitCode=1;}
  else{
   const vulnerabilities=Object.entries(audit.vulnerabilities??{}).map(([pkg,v])=>({
    package:pkg,severity:v.severity,direct:v.isDirect===true,
    affectedRange:typeof v.range==="string"?v.range.slice(0,100):"UNKNOWN",
    fixAvailable:typeof v.fixAvailable==="boolean"?v.fixAvailable:
     v.fixAvailable===null?null:"VERSION_OR_DEPENDENCY_CHANGE"
   }));
   const totals=audit.metadata?.vulnerabilities??{};
   console.log("PHASE14_PRODUCTION_ADVISORY_REPORT "+JSON.stringify({
    scope:"npm audit --omit=dev",total:vulnerabilities.length,totals,
    vulnerabilities:vulnerabilities.slice(0,100),runtimeReachability:"REQUIRES_SOURCE_REVIEW"}));
   if(vulnerabilities.some(v=>v.severity==="critical"||v.severity==="high")){
    console.error("PHASE14_HIGH_OR_CRITICAL_PRODUCTION_ADVISORIES_REQUIRE_TARGETED_TRIAGE");
    process.exitCode=1;
   }
  }
 }
}
