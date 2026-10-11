import React,{useCallback,useState} from "react";
import {createRoot} from "react-dom/client";
import { AssessmentApp } from "../../../packages/ui/src/AssessmentApp.js";
import { Phase15Mount } from "../../../packages/ui/src/Phase15Mount.js";
import "./styles.css";
function IsolatedPhase15MountShell(){
 // This switch exists only in a local/CI preview. It is never a Host login or tenant authority.
 const [tenant,setTenant]=useState("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
 const [session,setSession]=useState("ci-session-1");
 const [token,setToken]=useState(import.meta.env.VITE_DEV_TOKEN||"");
 const getToken=useCallback(()=>token,[token]);
 return <main>
  <button type="button" onClick={()=>setTenant(t=>t[0]==="a"?"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")}>Switch synthetic tenant hint</button>
  <button type="button" onClick={()=>setSession(x=>x==="ci-session-1"?"ci-session-2":"ci-session-1")}>Rotate test session</button>
  <button type="button" onClick={()=>setToken("invalid-isolated-preview-token")}>Invalidate synthetic token</button>
  <Phase15Mount apiOrigin={import.meta.env.VITE_API_BASE||"http://127.0.0.1:3001"} tenantContext={tenant}
   sessionRevision={session} accessToken={getToken}/>
 </main>;
}
const container = document.getElementById("root");
if(!container)throw new Error("Missing root");
const query=typeof window!=="undefined"?new URLSearchParams(window.location.search):new URLSearchParams();
if(query.has("phase15Mount"))createRoot(container).render(<React.StrictMode><IsolatedPhase15MountShell/></React.StrictMode>);
else createRoot(container).render(<React.StrictMode><AssessmentApp/></React.StrictMode>);
