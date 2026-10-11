/** GitHub private RC: verify exact digests plus actual archive member types and bytes. */
import {readFileSync,readdirSync,statSync} from "node:fs";
import {join,resolve} from "node:path";
import {createHash} from "node:crypto";
import {spawnSync} from "node:child_process";
import assert from "node:assert/strict";
const dir=resolve("build/phase15-release");
const manifest=JSON.parse(readFileSync(join(dir,"manifest.json"),"utf8"));
assert.equal(manifest.version,"0.15.0-rc.1");
assert.equal(manifest.productionHost,"HOST_AUTHORITY_NOT_CONFIGURED");
assert.equal(manifest.contractFreeze,"NOT_FROZEN");
const names=["api-service.tar.gz","api-worker.tar.gz","compatibility.json",
 "contract-schemas-draft.tar.gz","dependency-inventory.json",
 "postgres16-migrations-001-019.tar.gz","release-notes.md","sdk-private.tgz","ui-private.tgz"];
assert.deepEqual(manifest.artifacts.map(a=>a.name).sort(),names.sort());
assert.deepEqual(readdirSync(dir).sort(),[...names,"manifest.json","SHA256SUMS"].sort());
const sha=p=>createHash("sha256").update(readFileSync(p)).digest("hex");
const lines=readFileSync(join(dir,"SHA256SUMS"),"utf8").trim().split("\n");
assert.equal(lines.length,9);
const badFile=/(^|\/)(?:\.env(?:\.[^/]*)?|\.npmrc|id_rsa|id_ed25519|[^/]*\.pem|[^/]*\.key|\.git|node_modules|tests?|test-fixtures|\.cache|001_roles\.sql)(\/|$)/i;
const badBytes=/(?:api_family_worker_dev|api_family_dev|local_admin_only|postgres(?:ql)?:\/\/postgres:[^\s@]+@)/i;
function tar(args,archive,encoding="utf8"){
 const p=spawnSync("tar",[...args,archive],{encoding,timeout:60000,maxBuffer:32*1024*1024});
 assert.equal(p.status,0,"PHASE15_MALFORMED_OR_OVERSIZED_ARCHIVE");
 return p.stdout;
}
for(const item of manifest.artifacts){
 assert(!item.name.includes("/")&&!item.name.includes("\\")&&!item.name.includes(".."));
 const full=join(dir,item.name);
 assert.equal(statSync(full).size,item.bytes);
 assert.equal(sha(full),item.sha256);
 assert(lines.includes(item.sha256+"  "+item.name));
 if(item.name.endsWith(".tgz")||item.name.endsWith(".tar.gz")){
  const members=tar(["-tzf"],full).split("\n").filter(Boolean);
  const types=tar(["-tvzf"],full).split("\n").filter(Boolean);
  assert(members.length>1&&members.length===types.length,"PHASE15_ARCHIVE_MEMBER_COUNT");
  for(const row of types)assert(/^[d-]/.test(row),"PHASE15_ARCHIVE_SYMLINK_HARDLINK_OR_SPECIAL");
  for(const p of members){
   assert(!p.startsWith("/")&&!p.startsWith("\\")&&!/^[a-z]:[/\\]/i.test(p),"PHASE15_ARCHIVE_ABSOLUTE");
   assert(!p.split("/").includes("..")&&!p.includes("\\"),"PHASE15_ARCHIVE_TRAVERSAL");
   assert(!badFile.test(p)&&!p.includes("infrastructure/postgres-init"),"PHASE15_CREDENTIAL_FILE_DENIED");
  }
  const bytes=tar(["-xzOf"],full,null);
  assert(Buffer.isBuffer(bytes),"PHASE15_UNCOMPRESSED_CONTENT_UNAVAILABLE");
  assert(!badBytes.test(bytes.toString("utf8")),"PHASE15_CREDENTIAL_BYTES_DENIED");
  if(item.name==="api-service.tar.gz"){
   assert(members.some(p=>p.endsWith("/packages/service/src/server.js")));
   assert(members.some(p=>p.endsWith("/packages/discovery/src/worker-entry.mjs")));
  }
  if(item.name==="api-worker.tar.gz")assert(members.some(p=>p.endsWith("/packages/worker/src/main.js")));
  if(item.name==="postgres16-migrations-001-019.tar.gz"){
   const sql=members.filter(p=>/^\.\/migrations\/\d{3}[^/]*\.sql$/.test(p));
   assert.equal(sql.length,19);
   assert.deepEqual(sql.map(p=>p.match(/\/([0-9]{3})/)[1]).sort(),
    Array.from({length:19},(_,i)=>String(i+1).padStart(3,"0")));
   assert(members.every(p=>p==="."||p==="./"||p==="./migrations/"||/^\.\/migrations\/\d{3}[^/]*\.sql$/.test(p)),
    "PHASE15_MIGRATION_ARCHIVE_UNEXPECTED");
  }
  if(item.name==="sdk-private.tgz"){
   assert(members.some(p=>p.endsWith("/dist/v13.js")));
   assert(members.some(p=>p.endsWith("/dist/v13.d.ts")));
  }
  if(item.name==="ui-private.tgz"){
   assert(members.some(p=>p.endsWith("/dist/index.js")));
   assert(members.some(p=>p.endsWith("/dist/index.d.ts")));
  }
 }else assert(!badBytes.test(readFileSync(full,"utf8")),"PHASE15_CREDENTIAL_CONSTITUENT_DENIED");
}
console.log("PHASE15_ARTIFACT_SHA256_AND_INVENTORY_PASS:9");
console.log("PHASE15_ARCHIVE_CONTENT_CREDENTIAL_LINK_TRAVERSAL_DENIAL_PASS");
