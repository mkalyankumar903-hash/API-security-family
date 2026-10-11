/**
 * GitHub-hosted Phase15 private candidate build. Local outputs are ephemeral and NEVER published.
 * Run only after npm ci on a clean pinned checkout.
 */
import {readFileSync,writeFileSync,mkdirSync,cpSync,rmSync,readdirSync,statSync,existsSync,renameSync} from "node:fs";
import {join,resolve,relative} from "node:path";
import {spawnSync,execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
const version="0.15.0-rc.1",root=process.cwd();
const out=resolve("build/phase15-release"),stage=resolve("build/phase15-stage");
const call=(bin,args,opts={})=>{
 const result=spawnSync(bin,args,{cwd:root,encoding:"utf8",maxBuffer:8388608,...opts});
 if(result.status!==0)throw new Error("PHASE15_BUILD_FAILED:"+bin+":"+((result.stdout||"")+"\n"+(result.stderr||"")).slice(0,12000));
 return result.stdout.trim();
};
function copy(src,dest){mkdirSync(resolve(dest,".."),{recursive:true});cpSync(src,dest,{recursive:true});}
function sha(path){return createHash("sha256").update(readFileSync(path)).digest("hex");}
function tar(dir,name){
 const archive=join(out,name+".tar.gz");
 call("tar",["--sort=name","--mtime=@0","--owner=0","--group=0","--numeric-owner",
  "--format=gnu","-czf",archive,"-C",dir,"."]);
 return archive;
}
rmSync(out,{recursive:true,force:true});rmSync(stage,{recursive:true,force:true});
rmSync(resolve("build/phase15-runtime"),{recursive:true,force:true});
mkdirSync(out,{recursive:true});mkdirSync(stage,{recursive:true});
call("./node_modules/.bin/tsc",["--project","tsconfig.phase15.runtime.json"]);
call("./node_modules/.bin/tsc",["--project","packages/sdk/tsconfig.build.json"]);
call("./node_modules/.bin/vite",["build","--config","vite.phase15.config.ts"]);
call("./node_modules/.bin/tsc",["--project","tsconfig.phase15.ui.json"]);
copy("build/phase15-ui-types/packages/ui/src/Phase15Mount.d.ts","packages/ui/dist/index.d.ts");
copy("build/phase15-ui/index.js","packages/ui/dist/index.js");
for(const [which,main] of [["service","service"],["worker","worker"]]){
 const d=join(stage,which);
 mkdirSync(d,{recursive:true});
 copy("build/phase15-runtime/packages",join(d,"packages"));
 copy("packages/database/migrations",join(d,"packages/database/migrations"));
 copy("packages/discovery/src/worker-entry.mjs",join(d,"packages/discovery/src/worker-entry.mjs"));
 copy("packages/contracts/upstream-v032/schemas",join(d,"packages/contracts/upstream-v032/schemas"));
 copy("infrastructure/postgres-init",join(d,"infrastructure/postgres-init"));
 const rootPkg=JSON.parse(readFileSync("package.json","utf8"));
 const pkg={name:"@lumicsec/api-family-"+main+"-rc",version,private:true,type:"module",
  engines:{node:">=22 <23"},main:"./packages/"+main+"/src/"+(main==="service"?"server.js":"main.js"),
  dependencies:rootPkg.dependencies,scripts:{
   start:"node packages/"+main+"/src/"+(main==="service"?"server.js":"main.js"),
   migrate:"node packages/database/src/migrate.js"
  }};
 writeFileSync(join(d,"package.json"),JSON.stringify(pkg,null,2)+"\n");
 const lock=JSON.parse(readFileSync("package-lock.json","utf8"));
 lock.name=pkg.name;lock.version=version;
 lock.packages[""].name=pkg.name;lock.packages[""].version=version;
 lock.packages[""].dependencies=rootPkg.dependencies;
 delete lock.packages[""].devDependencies;
 writeFileSync(join(d,"package-lock.json"),JSON.stringify(lock,null,2)+"\n");
 // Exact package inventory excludes tests, TypeScript, production secrets and source maps.
 tar(d,"api-"+main);
}
const migrations=join(stage,"migrations");
copy("packages/database/migrations",join(migrations,"migrations"));
copy("infrastructure/postgres-init",join(migrations,"postgres-init"));
tar(migrations,"postgres16-migrations-001-019");
const contracts=join(stage,"contracts");
copy("packages/contracts/upstream-v032/schemas",join(contracts,"upstream-v032/schemas"));
copy("docs/CONTRACT_V032_SOURCE_MATRIX.md",join(contracts,"CONTRACT_V032_SOURCE_MATRIX.md"));
copy("docs/phase13-openapi.yaml",join(contracts,"phase13-openapi.yaml"));
copy("docs/api.openapi.yaml",join(contracts,"api.openapi.yaml"));
copy("packages/contracts/src/host-adapter-v15.ts",join(contracts,"host-adapter-v15.ts"));
tar(contracts,"contract-schemas-draft");
for(const [folder,name] of [["packages/sdk","sdk-private"],["packages/ui","ui-private"]]){
 const packed=JSON.parse(call("npm",["pack","./"+folder,"--ignore-scripts","--json","--pack-destination",out]));
 if(packed.length!==1||typeof packed[0].filename!=="string")throw new Error("PRIVATE_NPM_PACK_FAILED");
 const from=join(out,packed[0].filename);
 renameSync(from,join(out,name+".tgz"));
}
const rootLock=JSON.parse(readFileSync("package-lock.json","utf8"));
const inventory=Object.entries(rootLock.packages).filter(([p])=>p!=="").map(([path,detail])=>({
 path,version:detail.version||null,integrity:detail.integrity||null,dev:detail.dev===true,optional:detail.optional===true
})).sort((a,b)=>a.path.localeCompare(b.path));
writeFileSync(join(out,"dependency-inventory.json"),JSON.stringify({
 format:"phase15-lockfile-inventory-v1",source:"package-lock.json",sha256:sha("package-lock.json"),
 packages:inventory
},null,2)+"\n");
copy("docs/phase15-compatibility.json",join(out,"compatibility.json"));
copy("docs/phase15-release-notes.md",join(out,"release-notes.md"));
const checkForbidden=(dir)=>{
 const forbidden=/(^|\/)(\.env(?:\..*)?|id_rsa|id_ed25519|\.npmrc|.*\.pem|.*\.key|\.git|node_modules|tests?|test-fixtures|\.cache)(\/|$)/i;
 function walk(folder){
  for(const d of readdirSync(folder,{withFileTypes:true})){
   const file=join(folder,d.name),rel=relative(dir,file).replaceAll("\\","/");
   if(forbidden.test(rel))throw new Error("PHASE15_FORBIDDEN_PACKAGED_PATH:"+rel);
   if(d.isSymbolicLink())throw new Error("PHASE15_SYMLINK_FORBIDDEN");
   if(d.isDirectory())walk(file);
  }
 }
 walk(dir);
};
for(const p of ["service","worker","migrations","contracts"])checkForbidden(join(stage,p));
const files=readdirSync(out).filter(p=>!["manifest.json","SHA256SUMS"].includes(p)).sort();
const sourceSha=call("git",["rev-parse","HEAD"]);
const manifest={
 format:"lumicsec-api-family-release-candidate-v1",version,sourceSha,
 qualification:"NOT_YET_VERIFIED",publication:"PRIVATE_CI_ARTIFACTS_ONLY",
 productionHost:"HOST_AUTHORITY_NOT_CONFIGURED",contractFreeze:"NOT_FROZEN",
 migrations:"001-019 unchanged",node:">=22 <23",postgres:"16",
 artifacts:files.map(name=>({name,sha256:sha(join(out,name)),bytes:statSync(join(out,name)).size}))
};
writeFileSync(join(out,"manifest.json"),JSON.stringify(manifest,null,2)+"\n");
writeFileSync(join(out,"SHA256SUMS"),manifest.artifacts.map(a=>a.sha256+"  "+a.name).join("\n")+"\n");
console.log("PHASE15_ARTIFACT_GENERATION_COMPLETE:"+version+" sha="+sourceSha+" artifacts="+manifest.artifacts.length);
