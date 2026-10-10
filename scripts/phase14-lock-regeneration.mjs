/** Read-only GitHub-hosted tool for generating a reviewable fixed dependency lock.
 * Never pushes, publishes, sends secrets or changes production state. */
import {readFileSync,writeFileSync} from "node:fs";
import {execFileSync,spawnSync} from "node:child_process";
if(process.env.GITHUB_ACTIONS!=="true"||process.env.PHASE14_SYNTHETIC_LOCK_REGEN!=="true")
 throw Error("GH_HOSTED_LOCK_REGEN_ONLY");
const pkg=JSON.parse(readFileSync("package.json","utf8"));
function latest(name,major){
 const fetched=JSON.parse(execFileSync("npm",["view",name+"@"+major,"version","--json"],{
  encoding:"utf8",timeout:30000,maxBuffer:2*1024*1024
 }));
 const versions=Array.isArray(fetched)?fetched:[fetched];
 const candidates=versions.filter(v=>typeof v==="string"&&new RegExp("^"+major+"\\.\\d+\\.\\d+$").test(v));
 candidates.sort((a,b)=>{const x=a.split(".").map(Number),y=b.split(".").map(Number);
  for(let i=0;i<3;i++)if(x[i]!==y[i])return x[i]-y[i];return 0;});
 if(!candidates.length)throw Error("NO_STABLE_COMPATIBLE_RELEASE_"+name);
 return candidates[candidates.length-1];
}
const versions={fastify:latest("fastify",5),yaml:latest("yaml",2),ajv:latest("ajv",8)};
for(const [name,version] of Object.entries(versions))pkg.dependencies[name]=version;
writeFileSync("package.json",JSON.stringify(pkg,null,2)+"\\n");
const install=spawnSync("npm",["install","--package-lock-only","--ignore-scripts","--no-audit","--no-fund"],{
 encoding:"utf8",timeout:120000,maxBuffer:8*1024*1024});
if(install.error||install.status!==0)throw Error("LOCK_REGEN_INSTALL_FAILED_"+String(install.status)+"_"+(install.stderr??"").slice(0,500));
const audit=spawnSync("npm",["audit","--omit=dev","--json"],{encoding:"utf8",timeout:90000,maxBuffer:12*1024*1024});
if(audit.error)throw Error("LOCK_REGEN_AUDIT_UNAVAILABLE");
let report;try{report=JSON.parse(audit.stdout??"");}catch{throw Error("LOCK_REGEN_AUDIT_INVALID");}
if(report.error)throw Error("LOCK_REGEN_AUDIT_ERROR_"+String(report.error.code??"UNKNOWN"));
const high=Object.entries(report.vulnerabilities??{}).filter(([,x])=>x.severity==="high"||x.severity==="critical");
console.log("PHASE14_LOCK_REGEN_VERSIONS "+JSON.stringify(versions));
console.log("PHASE14_LOCK_REGEN_ADVISORY_COUNTS "+JSON.stringify(report.metadata?.vulnerabilities??{}));
if(high.length)throw Error("REPAIRED_LOCK_STILL_HAS_HIGH_OR_CRITICAL_"+high.map(([p])=>p).join("_"));
for(const [label,path] of [["LOCK","package-lock.json"],["PACKAGE","package.json"]]){
 const text=JSON.stringify(readFileSync(path,"utf8"));
 for(let i=0;i<text.length;i+=2500)console.log("PHASE14_"+label+"_CHUNK|"+i+"|"+text.slice(i,i+2500));
}
console.log("PHASE14_LOCK_REGEN_COMPLETE");
