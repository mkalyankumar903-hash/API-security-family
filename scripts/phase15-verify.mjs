import {readFileSync,readdirSync,statSync,mkdirSync,rmSync} from "node:fs";
import {join,resolve} from "node:path";
import {createHash} from "node:crypto";
import {spawnSync} from "node:child_process";
import assert from "node:assert/strict";
const dir=resolve("build/phase15-release"),manifest=JSON.parse(readFileSync(join(dir,"manifest.json"),"utf8"));
assert.equal(manifest.version,"0.15.0-rc.1");
assert.equal(manifest.productionHost,"HOST_AUTHORITY_NOT_CONFIGURED");
assert.equal(manifest.contractFreeze,"NOT_FROZEN");
const hashed=a=>createHash("sha256").update(readFileSync(a)).digest("hex");
const lines=readFileSync(join(dir,"SHA256SUMS"),"utf8").trim().split("\n");
assert.equal(lines.length,manifest.artifacts.length);
for(const entry of manifest.artifacts){
 const full=join(dir,entry.name);
 assert.equal(statSync(full).size,entry.bytes);
 assert.equal(hashed(full),entry.sha256);
 assert(lines.includes(entry.sha256+"  "+entry.name));
 if(entry.name.endsWith(".tgz")||entry.name.endsWith(".tar.gz")){
  const p=spawnSync("tar",["-tzf",full],{encoding:"utf8"});
  assert.equal(p.status,0,entry.name+": invalid archive");
  const paths=p.stdout.split("\n");
  assert(paths.length>2,entry.name+": empty archive");
  for(const f of paths){
   assert(!f.includes("../"),entry.name+": traversal");
   assert(!/(^|\/)\.env($|\/|\.)|(^|\/)\.npmrc$|(^|\/)id_rsa$|\.pem$|\.key$|\/node_modules\/|\/tests?\//i.test(f),entry.name+": unsafe path "+f);
  }
  if(entry.name==="api-service.tar.gz")assert(paths.some(x=>x.endsWith("/packages/service/src/server.js")));
  if(entry.name==="api-worker.tar.gz")assert(paths.some(x=>x.endsWith("/packages/worker/src/main.js")));
  if(entry.name==="postgres16-migrations-001-019.tar.gz")assert.equal(paths.filter(x=>/^\.\/migrations\/\d{3}.*\.sql$/.test(x)).length,19);
  if(entry.name==="sdk-private.tgz"){assert(paths.some(x=>x.endsWith("/dist/v13.js")));assert(paths.some(x=>x.endsWith("/dist/v13.d.ts")));}
  if(entry.name==="ui-private.tgz"){assert(paths.some(x=>x.endsWith("/dist/index.js")));assert(paths.some(x=>x.endsWith("/dist/index.d.ts")));}
 }
}
console.log("PHASE15_ARTIFACT_SHA256_AND_INVENTORY_PASS:"+manifest.artifacts.length);
