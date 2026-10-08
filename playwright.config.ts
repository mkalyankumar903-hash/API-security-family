import {defineConfig} from "@playwright/test";
export default defineConfig({
  testDir:"./tests/browser",
  fullyParallel:false,
  workers:1,
  retries:0,
  timeout:40000,
  use:{
    baseURL:"http://127.0.0.1:5173",
    browserName:"chromium",
    headless:true,
    launchOptions:{executablePath:process.env.CHROMIUM_BINARY||undefined},
    trace:"retain-on-failure"
  },
  webServer:[
    {command:"npm run api",url:"http://127.0.0.1:3001/health/live",timeout:45000,reuseExistingServer:false},
    {command:"npm run dev",url:"http://127.0.0.1:5173",timeout:45000,reuseExistingServer:false}
  ],
  reporter:[["list"],["html",{open:"never"}]],
  outputDir:"test-results"
});
