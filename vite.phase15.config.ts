import {defineConfig} from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
 plugins:[react()],
 build:{outDir:"build/phase15-ui",emptyOutDir:true,lib:{
  entry:"packages/ui/src/Phase15Mount.tsx",name:"LumicSecApiPhase15",formats:["es"],fileName:()=>"index.js"
 },rollupOptions:{external:["react","react/jsx-runtime"]},sourcemap:false}
});
