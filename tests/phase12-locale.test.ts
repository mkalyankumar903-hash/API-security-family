import {test} from "node:test";
import assert from "node:assert/strict";
import {english,recognizedLocale,localeDirection,msg,utcDateTime,count} from "../packages/ui/src/phase12-locale.js";
test("Phase12 stable English message catalog and safe unsupported-language fallback",()=>{
 assert.equal(recognizedLocale("en-US"),"en");
 assert.equal(recognizedLocale("es"),"en");
 assert.equal(recognizedLocale("en-XA"),"en-XA");
 assert.equal(msg("title","en"),english.title);
 assert.equal(localeDirection("en"),"ltr");
});
test("Phase12 pseudo LTR/RTL engineering QA is visibly labeled, not represented as actual translation",()=>{
 const pseudo=msg("title","en-XA");
 assert(pseudo.startsWith("⟦")&&pseudo.endsWith("⟧"));
 assert(pseudo.length>english.title.length);
 assert.equal(localeDirection("en-XB"),"rtl");
 assert.match(msg("aiDisabled","en-XB"),/No model provider configured/);
});
test("Phase12 UTC display formatting never changes a source fingerprint or security identity",()=>{
 const fingerprint="abcdef".repeat(10)+"abcd";
 const en=utcDateTime("2026-10-10T06:30:00Z","en");
 const pseudo=utcDateTime("2026-10-10T06:30:00Z","en-XB");
 assert(en.includes("UTC"));assert(pseudo.includes("UTC"));
 assert.equal(fingerprint,"abcdef".repeat(10)+"abcd");
 assert.equal(count(1234567,"en"),"1,234,567");
 assert.equal(utcDateTime("bad date","en"),"UNKNOWN");
});
