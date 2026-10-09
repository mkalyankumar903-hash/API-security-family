import {test} from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";
import React from "react";
import {migrate,pool} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {drainQueue} from "../packages/worker/src/index.js";
test("React renders real PostgreSQL backed inventory and assessment report",async()=>{
  process.env.SYNTHETIC_AUTH_ENABLED="true";
  process.env.DEV_TOKENS_JSON=JSON.stringify({"local-test-token-alpha":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"});
  await migrate();
  const app=await makeApp();
  const token="local-test-token-alpha";
  const auth={authorization:"Bearer "+token};
  const target=await app.inject({method:"POST",url:"/v1/targets",headers:auth,payload:{name:"UI Fixture "+crypto.randomUUID(),baseUrl:"https://api.fixture.invalid",environment:"SYNTHETIC"}});
  assert.equal(target.statusCode,201);
  const id=target.json().id;
  const text=readFileSync(new URL("../fixtures/insecure.openapi.json",import.meta.url),"utf8");
  assert.equal((await app.inject({method:"POST",url:"/v1/targets/"+id+"/specifications",headers:auth,payload:{filename:"ui.json",content:text}})).statusCode,201);
  const dom=new JSDOM("<!DOCTYPE html><html><body><div id='root'></div></body></html>",{url:"http://localhost:5173"});
  const oldWindow=globalThis.window, oldDoc=globalThis.document, oldFetch=globalThis.fetch;
  Object.assign(globalThis,{window:dom.window,document:dom.window.document,HTMLElement:dom.window.HTMLElement,MutationObserver:dom.window.MutationObserver,IS_REACT_ACT_ENVIRONMENT:true});
  globalThis.fetch=async(url:RequestInfo|URL,options?:RequestInit):Promise<Response>=>{
    const u=new URL(String(url));
    const headers=options?.headers as Record<string,string> | undefined;
    const response=await app.inject({method:(options?.method??"GET") as "GET"|"POST",url:u.pathname+u.search,headers, payload:options?.body?.toString()});
    return new Response(response.body,{status:response.statusCode,headers:{"content-type":"application/json"}});
  };
  const {render,screen,fireEvent,waitFor,cleanup,act}=await import("@testing-library/react");
  const {AssessmentApp}=await import("../packages/ui/src/AssessmentApp.js");
  try{
    render(React.createElement(AssessmentApp,{initialToken:token}),{container:dom.window.document.getElementById("root")!});
    await waitFor(()=>assert.ok((screen.getByLabelText("Select target") as HTMLSelectElement).options.length>=2));
    fireEvent.change(screen.getByLabelText("Select target"),{target:{value:id}});
    await screen.findByText("/admin/accounts",{}, {timeout:10000});
    fireEvent.click(screen.getByText("Start SPEC_ONLY assessment"));
    await screen.findByText(/Assessment status:/);
    await act(async()=>{await drainQueue();});
    await screen.findByText("4. Evidence-backed report",{}, {timeout:8000});
    assert.ok(screen.getByText(/Runtime validation: false/));
    assert.ok(screen.getAllByText("SPEC_OBSERVATION · SPEC_ONLY · Review required").length>0);
  }finally{
    cleanup();
    globalThis.fetch=oldFetch;
    Object.assign(globalThis,{window:oldWindow,document:oldDoc});
    dom.window.close();
    await app.close();await pool.end();
  }
});
