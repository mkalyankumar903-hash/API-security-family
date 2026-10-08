import React from "react";
import {createRoot} from "react-dom/client";
import { AssessmentApp } from "../../../packages/ui/src/AssessmentApp.js";
import "./styles.css";
const container = document.getElementById("root");
if (!container) throw new Error("Missing root");
createRoot(container).render(<React.StrictMode><AssessmentApp /></React.StrictMode>);
