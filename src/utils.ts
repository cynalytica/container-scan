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
  core.info(JSON.stringify(files))
  for(let i=0;i<files.length;i++){
    const filename=path.join(dir,files[i]);
    if (/\.sarif.json$/.test(filename)) sarifs.push(fileHelper.getFileJson(filename) as SarifFormat);
  }
  const mainFile: SarifFormat = sarifs[0];
  mainFile.runs = sarifs.map((sarif) => sarif.runs).reduce((cur, agg) => [...agg, ...cur])

  fileHelper.writeFileJson(`${dir}/trivy.sarif.json`,mainFile)
  core.setOutput('sarif-report-path',`${dir}/trivy.sarif.json`)
}



export function addLogsToDebug(outputPath: string) {
  const out = fs.readFileSync(outputPath, 'utf8');
  core.debug(out);
}