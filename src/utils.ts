import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';
import * as fileHelper from "./fileHelper";
import { StaticAnalysisResultsFormatSARIFVersion210Rtm0JSONSchema as SarifFormat, Run as SarifRun } from "./sarif/interfaces";

export function extractErrorsFromLogs(outputPath: string, toolName?: string): any {
  const out = fs.readFileSync(outputPath, 'utf8');
  const lines = out.split('\n');
  let errors = [];
  lines.forEach((line) => {
    const errIndex = line.indexOf("FATAL");
    if (errIndex >= 0) {
      const err = line.substring(errIndex);
      errors.push(err);
    }
  });
  return errors;
}

export async function concatSarifs(){
  const dir = fileHelper.getContainerScanDirectory();
  const sarifs:  SarifFormat[] = []
  if (!fs.existsSync(dir)){
    throw new Error("unable to find container scan directory")
  }
  const files=fs.readdirSync(dir);
  for(let i=0;i<files.length;i++){
    const filename=path.join(dir,files[i]);
    if (/\.sarif.json$/.test(filename)) sarifs.push(fileHelper.getFileJson(filename) as SarifFormat);
  }
  const mainFile: SarifFormat = sarifs[0];
  mainFile.runs = sarifs.map((sarif) => sarif.runs).reduce((cur, agg) => [...agg, ...cur])

  fileHelper.writeJsonFile(`${dir}/trivy.sarif.json`,mainFile)
  core.setOutput('sarif-report-path',`${dir}/trivy.sarif.json`)
}

export async function  createHtmlOutput(){
  const dir = fileHelper.getContainerScanDirectory();
  const files=fs.readdirSync(dir);
  const htmlFiles :string[] = []
  for(let i=0;i<files.length;i++){
    const filename=path.join(dir,files[i]);
    if (/\.html$/.test(filename)) htmlFiles.push(files[i]);
  }
  fileHelper.writeFile(`${dir}/index.html`,indexHtmlFile(htmlFiles));
  core.setOutput('audit-reports-path',`${dir}/*.html`)

}


function indexHtmlFile(files:string[]){
  const dateString=new Date().toString()
  return `<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>Container Scan Report ${dateString}</title>
    <style>
        * {
            font-family:  Inter UI,-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol;
            font-feature-settings:"calt" 1,"kern" 1,"liga" 1,"tnum" 1;
        }
     </style>
</head>
<h1>Container Scan Report ${dateString}</h1>
${arrayToList(files)}
</html>`
}


function arrayToList(arr:string[]): string {

  let ret = ""

  if(arr === undefined || arr === null){
    return ret
  }
  arr.forEach(s => ret += `<li><a href="${s}">${s.replace(".html","")}</a></li>`)
  return `<ul>${ret}</ul>`

}

export function addLogsToDebug(outputPath: string) {
  const out = fs.readFileSync(outputPath, 'utf8');
  core.debug(out);
}
export function addLogsToError(outputPath: string) {
  const out = fs.readFileSync(outputPath, 'utf8');
  core.debug(out);
}