/** Complete private API source transfer for approved Main Platform integration review. */
import assert from "node:assert/strict";
import {execFileSync,spawnSync} from "node:child_process";
import {readFileSync,writeFileSync,mkdirSync,copyFileSync,rmSync,lstatSync} from "node:fs";
import {join,dirname,resolve} from "node:path";
import {createHash} from "node:crypto";
import {mkdtempSync} from "node:fs";
import {tmpdir} from "node:os";
assert.equal(process.env.GITHUB_ACTIONS,"true","TRANSFER_REQUIRES_PRIVATE_GITHUB_ACTIONS");
const sourceSha=execFileSync("git",["rev-parse","HEAD"],{encoding:"utf8"}).trim();
const out=resolve("build/phase15-main-platform-transfer"),stage=resolve("build/phase15-main-platform-staging");
const sha=b=>createHash("sha256").update(b).digest("hex");
const tracked=execFileSync("git",["ls-files","-z"]).toString("utf8").split("\0").filter(Boolean).sort();
const valid=p=>p.startsWith("packages/")||p.startsWith("apps/")||p.startsWith("docs/")||
 p.startsWith("scripts/")||p.startsWith("tests/")||p.startsWith("fixtures/")||
 p.startsWith(".github/workflows/")||["package.json","package-lock.json","README.md",
 "AGENTS.md","Dockerfile.phase15",".dockerignore","eslint.config.js","playwright.config.ts",
 "vite.config.ts","vite.phase15.config.ts","tsconfig.json","tsconfig.phase15.runtime.json",
 "tsconfig.phase15.ui.json"].includes(p);
const forbidden=p=>p.startsWith("infrastructure/")||p.startsWith(".env")||
 p.split("/").some(x=>x===".."||x==="node_modules"||x==="build"||x===".git")||
 /(?:\.pem|\.key|\/\.npmrc|\/001_roles\.sql)$/.test(p);
const paths=tracked.filter(p=>valid(p)&&!forbidden(p));
const sql=paths.filter(p=>/^packages\/database\/migrations\/\d{3}_[^/]+\.sql$/.test(p));
assert(paths.length>=200,"FULL_SOURCE_COVERAGE_REQUIRED");
assert.equal(sql.length,19,"CANONICAL_API_MIGRATIONS_001_019_REQUIRED");
assert.deepEqual(sql.map(p=>p.match(/\/([0-9]{3})_/)[1]),
 Array.from({length:19},(_,i)=>String(i+1).padStart(3,"0")));
const kind=p=>p.startsWith("packages/database/migrations/")?"SQL_NOT_FOR_MAIN_SUPABASE":
 p.startsWith("packages/service/")?"FASTIFY_SERVICE":p.startsWith("packages/worker/")?"PRIVATE_WORKER":
 p.startsWith("packages/sdk/")?"PRIVATE_SDK":p.startsWith("packages/ui/")?"REACT_UI":
 p.startsWith("packages/contracts/")?"UNFROZEN_CONTRACTS":p.startsWith("packages/database/")?"POSTGRES_RLS":
 p.startsWith("packages/")?"API_ENGINE":p.startsWith("tests/")||p.startsWith("fixtures/")?"SYNTHETIC_TEST_ONLY":
 p.startsWith("scripts/")||p.startsWith(".github/")?"BUILD_TEST_ONLY":"SOURCE_AND_DOCS";
const dir="integrations/api-family/source",files=[],environmentNames={};
const trackedVars=["packages/service/","packages/worker/","packages/database/","packages/sdk/","packages/ui/","scripts/"];
if(process.argv.includes("--verify")){
 const inv=JSON.parse(readFileSync(join(out,"source-inventory.json"),"utf8"));
 assert.equal(inv.sourceSha,sourceSha);assert.equal(inv.migrations.count,19);
 const archive=join(out,"api-family-source.tar.gz");
 const sums=readFileSync(join(out,"SHA256SUMS"),"utf8").trim().split("\n");
 assert.deepEqual(sums,[sha(readFileSync(archive))+"  api-family-source.tar.gz",
  sha(readFileSync(join(out,"source-inventory.json")))+"  source-inventory.json"]);
 const ls=spawnSync("tar",["-tzf",archive],{encoding:"utf8",timeout:90000,maxBuffer:20*1024*1024});
 const types=spawnSync("tar",["-tvzf",archive],{encoding:"utf8",timeout:90000,maxBuffer:20*1024*1024});
 assert.equal(ls.status,0);assert.equal(types.status,0);
 const members=ls.stdout.split("\n").filter(x=>x&&!x.endsWith("/"));
 for(const p of members)assert(!p.startsWith("/")&&!p.includes("\\")&&!p.split("/").includes("..")&&
  !p.includes("postgres-init")&&!p.endsWith("001_roles.sql")&&!p.includes("/.env"),"UNSAFE_TRANSFER_MEMBER");
 for(const line of types.stdout.split("\n").filter(Boolean))assert(/^[d-]/.test(line),"UNSAFE_LINK_MEMBER");
 const tmp=mkdtempSync(join(tmpdir(),"api-family-source-"));
 try{
  const tar=spawnSync("tar",["-xzf",archive,"-C",tmp],{encoding:"utf8",timeout:90000});
  assert.equal(tar.status,0,"SOURCE_EXTRACT_FAILED");
  const wanted=new Set();
  for(const entry of inv.files){
   assert.equal(entry.destination,dir+"/"+entry.source);
   assert(!wanted.has(entry.destination));wanted.add(entry.destination);
   const a=join(tmp,entry.destination),b=entry.source;
   assert(lstatSync(a).isFile()&&!lstatSync(a).isSymbolicLink());
   const bytes=readFileSync(a),orig=readFileSync(b);
   assert.equal(bytes.length,entry.bytes,"TRANSFER_SIZE:"+b);
   assert.equal(sha(bytes),entry.sha256,"TRANSFER_SHA:"+b);
   assert.equal(sha(orig),entry.sha256,"SOURCE_DRIFT:"+b);
  }
  assert.equal(members.length,wanted.size,"TRANSFER_FILE_COUNT");
  for(const m of members)assert(wanted.has(m),"UNDECLARED_TRANSFER_PATH:"+m);
  assert.equal(inv.files.filter(f=>f.kind==="SQL_NOT_FOR_MAIN_SUPABASE").length,19);
  for(const f of ["packages/service/src/server.ts","packages/worker/src/main.ts",
    "packages/database/src/migrate.ts","packages/sdk/src/v13.ts","packages/ui/src/Phase15Mount.tsx",
    "packages/contracts/src/host-adapter-v15.ts","package-lock.json",".github/workflows/phase15.yml"])
   assert(inv.files.some(e=>e.source===f),"SOURCE_REQUIRED:"+f);
  console.log("PHASE15_MAIN_PLATFORM_FULL_SOURCE_TRANSFER_SHA256_PASS files="+wanted.size+" sql=19");
 }finally{rmSync(tmp,{recursive:true,force:true});}
}else{
 rmSync(out,{recursive:true,force:true});rmSync(stage,{recursive:true,force:true});
 mkdirSync(out,{recursive:true});mkdirSync(stage,{recursive:true});
 for(const p of paths){
  assert(!p.includes("\\")&&!p.startsWith("/")&&!p.split("/").includes(".."));
  const st=lstatSync(p);assert(st.isFile()&&!st.isSymbolicLink(),"UNSAFE_SOURCE:"+p);
  const bytes=readFileSync(p),dst=join(stage,dir,p);
  assert(!bytes.toString("utf8").includes("-----BEGIN PRIVATE KEY-----"),"PRIVATE_KEY_IN_SOURCE:"+p);
  mkdirSync(dirname(dst),{recursive:true});copyFileSync(p,dst);
  files.push({source:p,destination:dir+"/"+p,kind:kind(p),bytes:bytes.length,sha256:sha(bytes)});
  const key=trackedVars.find(prefix=>p.startsWith(prefix));
  if(key){
   const values=environmentNames[key]??new Set();
   for(const m of bytes.toString("utf8").matchAll(/process\.env(?:\.([A-Z][A-Z0-9_]*)|\[['"]([A-Z][A-Z0-9_]*)['"]\])/g))
    values.add(m[1]||m[2]);
   environmentNames[key]=values;
  }
 }
 const inventory={format:"lumicsec-api-family-private-source-transfer-v1",sourceSha,
 sourceRepository:"mkalyankumar903-hash/API-security-family",
 integrationDestination:"kalyankumarmalli480-sys/lumicsec-security-platform",
 destinationSourceRoot:dir,files,
 migrations:{count:19,paths:sql,approvedReplayTarget:"ISOLATED_POSTGRESQL16_ONLY",
 mainSupabase:"DENY",reasons:["public.api_* tables","public SECURITY DEFINER functions","api_queue schema",
 "api_family/queue/QA roles","api.tenant_id transaction context"]},
 envVariableNames:Object.fromEntries(Object.entries(environmentNames).map(([k,v])=>[k,[...v].sort()])),
 exclusions:["infrastructure/* including CI role-bootstrap passwords",".env*", "untracked/generated build/*"],
 consent:"SOURCE_TRANSFER_ONLY_NO_MAIN_PLATFORM_MUTATION_OR_PRODUCTION_AUTHORITY",
 contracts:"PROPOSED_NOT_FROZEN",customerScanning:"DENIED"};
 const mf=join(out,"source-inventory.json");writeFileSync(mf,JSON.stringify(inventory,null,2)+"\n");
 const tar=join(out,"api-family-source.tar.gz");
 const p=spawnSync("tar",["--sort=name","--mtime=@0","--owner=0","--group=0",
 "--numeric-owner","--format=gnu","-czf",tar,"-C",stage,"integrations"],
 {encoding:"utf8",timeout:120000});
 assert.equal(p.status,0,"TRANSFER_TAR_FAILED:"+String(p.stderr).slice(0,800));
 writeFileSync(join(out,"SHA256SUMS"),sha(readFileSync(tar))+"  api-family-source.tar.gz\n"+
  sha(readFileSync(mf))+"  source-inventory.json\n");
 console.log("PHASE15_MAIN_PLATFORM_SOURCE_TRANSFER_GENERATED files="+files.length+" sql=19 sha="+sourceSha);
}
