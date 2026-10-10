/** Phase12 UI catalog with explicit pseudo-locale QA, never fake customer translations. */
export const english={
 title:"Unified API security workspace — Phase 12",
 summary:"Read-only evidence and reporting over existing synthetic-only assessment engines. No customer production scanning or verified-fixed authority.",
 overview:"Evidence-backed overview",
 targets:"Actual target lifecycles",
 assessments:"Actual assessment status and engine",
 history:"Historical assessments",
 historyHelp:"Past runs are retrieved from the authorized PostgreSQL tenant, not browser-generated results.",
 selectReport:"Select a completed immutable composite report",
 selectReportOption:"Choose authorized report",
 report:"Immutable report presentation",
 correlated:"Correlated findings and remediation",
 noFindings:"No observed findings. This does not establish security.",
 limits:"Limitations",
 ai:"Optional read-only AI",
 aiDisabled:"No model provider configured or invoked. The assistant cannot start scans or change security evidence.",
 jsonDownload:"Download authorized JSON presentation",
 pdfDownload:"Download authorized PDF report",
 language:"Interface locale (English and test-only pseudo-locales)",
 loading:"Loading authorized evidence…",
 reportUnavailable:"Report not available for this tenant",
} as const;
export type MessageKey=keyof typeof english;
export type Phase12Locale="en"|"en-XA"|"en-XB";
export function recognizedLocale(input:unknown):Phase12Locale{
 return input==="en-XA"||input==="en-XB"?input:"en";
}
export function localeDirection(locale:Phase12Locale):"ltr"|"rtl"{
 return locale==="en-XB"?"rtl":"ltr";
}
export function msg(key:MessageKey,locale:Phase12Locale):string{
 const source=english[key];
 if(locale==="en-XA")return "⟦"+source.replace(/[aeiouAEIOU]/g,ch=>ch+ch)+"⟧";
 if(locale==="en-XB")return "⟦"+source+"⟧";
 return source;
}
export function utcDateTime(value:string,locale:Phase12Locale):string{
 const date=new Date(value);
 if(!Number.isFinite(date.valueOf()))return "UNKNOWN";
 return new Intl.DateTimeFormat(locale==="en"?"en":"en-US",{
  dateStyle:"medium",timeStyle:"short",timeZone:"UTC"
 }).format(date)+" UTC";
}
export function count(value:number,locale:Phase12Locale):string{
 if(!Number.isFinite(value))return "UNKNOWN";
 return new Intl.NumberFormat(locale==="en"?"en":"en-US").format(value);
}
