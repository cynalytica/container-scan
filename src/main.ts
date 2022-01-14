import * as core from '@actions/core';
// import * as dockleHelper from './dockleHelper';
import * as inputHelper from './inputHelper';
import * as allowedlistHandler from './allowedlistHandler';
import * as trivyHelper from './trivyHelper';
import * as utils from './utils';
import * as issueHelper from './createIssue'
import {getSecurityLevel, SecurtiyLabels} from "./createIssue";

export async function run(): Promise<void> {
    inputHelper.validateRequiredInputs();
    allowedlistHandler.init();
    const images = inputHelper.imageNames.split(/\s|,/).filter(v => v !== "")//white space or comma seperated. remove any empty ones also.
    console.log(images)
    await Promise.allSettled(images.map(runImage))
}


function arrayToMDlist(arr:string[]): string {
    let ret = ""
    arr.forEach(s => ret += `* [${s}](${s})\r\n`)
    return ret

}

async function createIssueFromVuln(vuln:trivyHelper.FilterOutput,imageName:string) {

    if(getSecurityLevel(inputHelper.minSeverity) >= getSecurityLevel(vuln.severity)) {
        console.log(`${inputHelper.minSeverity} ${vuln.severity}`)
        //figure out labels
        const title = `${imageName} ${vuln.vulnerabilityId}`
        const body = `# ${vuln.vulnerabilityId}

${vuln.title}

${vuln.description}

## Version
${vuln.version}

## Fixed Version
${vuln.fixedVersion || `None`} 

## Severity Source
${vuln.severity}

${vuln.severitySource}

## References

${arrayToMDlist(vuln.references)}
`
        const issue: issueHelper.Issue = {
            title,
            body,
            labels: SecurtiyLabels[vuln.severity],
        }
        await issueHelper.createAnIssue(issue)
    }


}
async function runImage(image){
    const trivyResult = await trivyHelper.runTrivy(image);
    const trivyStatus = trivyResult.status;
    console.log(trivyResult)
    if (trivyStatus === trivyHelper.TRIVY_EXIT_CODE) {
        //create issues here?!
        const vulns = trivyHelper.getFilteredOutput();
        vulns.forEach(v => createIssueFromVuln(v,image))
    } else if (trivyStatus === 0) {
        core.info("No vulnerabilities were detected in the container image");
    } else {
        const errors = utils.extractErrorsFromLogs(trivyHelper.getTrivyLogPath(), trivyHelper.trivyToolName);
        errors.forEach(err => {
            core.error(err);
        });
        throw new Error(`An error occurred while scanning container image: ${image} for vulnerabilities.`);
    }

    // let dockleStatus: number;
    // if (inputHelper.isRunQualityChecksEnabled()) {
    //     dockleStatus = await dockleHelper.runDockle();
    //     if (dockleStatus === dockleHelper.DOCKLE_EXIT_CODE) {
    //         dockleHelper.printFormattedOutput();
    //     } else if (dockleStatus === 0) {
    //         console.log("No best practice violations were detected in the container image");
    //     } else {
    //         const errors = utils.extractErrorsFromLogs(dockleHelper.getDockleLogPath(), dockleHelper.dockleToolName);
    //         errors.forEach(err => {
    //             core.error(err);
    //         });
    //         throw new Error("An error occurred while scanning the container image for best practice violations");
    //     }
    // }
    //
    // try {
    //     await utils.createScanResult(trivyStatus, dockleStatus);
    // } catch (error) {
    //     core.warning(`An error occurred while creating the check run for container scan. Error: ${error}`);
    // }
    //
    // const scanReportPath = utils.getScanReport(trivyResult, dockleStatus);
    // core.setOutput('scan-report-path', scanReportPath);
    //
    // if (trivyStatus == trivyHelper.TRIVY_EXIT_CODE) {
    //     throw new Error("Vulnerabilities were detected in the container image");
    // }
}

run().catch(error => core.setFailed(error.message));