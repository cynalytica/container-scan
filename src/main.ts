import * as core from '@actions/core';
import * as inputHelper from './inputHelper';
import * as allowedlistHandler from './allowedlistHandler';
import * as trivyHelper from './trivyHelper';
import * as utils from './utils';
import * as issueHelper from './createIssue'
import { concatSarifs } from "./utils";

export async function run(): Promise<void> {
    inputHelper.validateRequiredInputs();
    allowedlistHandler.init();
    await trivyHelper.getTrivy()//get trivy download first this will prevent multiple downloads.
    const images = inputHelper.imageNames.split(/\s|,/).filter(v => v !== "")//white space or comma seperated. remove any empty ones also.
    await issueHelper.getIssuesList(issueHelper.globalClient)// populate issues here.
    await Promise.allSettled(images.map(runImageSarif))
    await concatSarifs()
    if(inputHelper.isRunIssueCreateEnabled()){
        await Promise.allSettled(images.map(runImage))
    }
    //TODO: create audit log output (configurable output location)


}

function arrayToMDlist(arr:string[]): string {

    let ret = ""
    if(arr === undefined || arr === null){
        return ret
    }
    arr.forEach(s => ret += `* [${s}](${s})\r\n`)
    return ret

}

async function createIssueFromVuln(vuln:trivyHelper.FilterOutput,imageName:string) {
    const severities = trivyHelper.getSeveritiesToInclude();
    if(severities.includes(vuln.severity)) {
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
        //Add in the no-fix label
        const labels = issueHelper.SecurtiyLabels[vuln.severity]
        if(vuln.fixedVersion === undefined){
            labels.push('no-fix')
        }
        const issue: issueHelper.Issue = {
            title,
            body,
            labels: labels,
        }
        await issueHelper.createAnIssue(issueHelper.globalClient,issueHelper.issues,issue,vuln.fixedVersion)
    }


}



async function runImageSarif(image:string) {
    const trivyResult = await trivyHelper.runTrivySarif(image)
    const trivyStatus = trivyResult.status;
    if (trivyStatus === trivyHelper.TRIVY_EXIT_CODE) {
        const vulns = trivyHelper.getFilteredOutput(image);
        core.info(`Vulnerabilities were detected in the container ${image} ${vulns.length}`);
    } else if (trivyStatus === 0) {
        core.info(`No vulnerabilities were detected in the container ${image}`);
    }
}

async function runImage(image){
    const trivyResult = await trivyHelper.runTrivy(image);
    const trivyStatus = trivyResult.status;
    if (trivyStatus === trivyHelper.TRIVY_EXIT_CODE) {
        //create issues here?!
        const vulns = trivyHelper.getFilteredOutput(image);
        vulns.forEach(v => createIssueFromVuln(v,image))

        // vulns.forEach(v => createIssueFromVuln(v,image))
        //create a AUDIT entry for image.
    } else if (trivyStatus === 0) {
        core.info("No vulnerabilities were detected in the container image");
    } else {
        const errors = utils.extractErrorsFromLogs(trivyHelper.getTrivyLogPath(image), trivyHelper.trivyToolName);
        errors.forEach(err => {
            core.error(err);
        });
        throw new Error(`An error occurred while scanning container image: ${image} for vulnerabilities.`);
    }
}

run().catch(error => core.setFailed(error.message));