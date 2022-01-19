import * as core from '@actions/core';
import * as inputHelper from './inputHelper';
import * as allowedlistHandler from './allowedlistHandler';
import * as trivyHelper from './trivyHelper';
import * as utils from './utils';
import * as issueHelper from './createIssue'
import {addLogsToError, concatSarifs, createHtmlOutput} from "./utils";
import {SARIFTemplate} from "./sarif/sarif";
import {HTMLTableTemplate} from "./sarif/table";
import {getOutputPath, getTrivySarifOutputPath} from "./trivyHelper";

export async function run(): Promise<void> {
    inputHelper.validateRequiredInputs();
    allowedlistHandler.init();
    await trivyHelper.getTrivy()//get trivy download first this will prevent multiple downloads.
    const images = inputHelper.imageNames.split(/\s|,/).filter(v => v !== "")//white space or comma seperated. remove any empty ones also.
    if(inputHelper.isRunIssueCreateEnabled()){
        await issueHelper.getIssuesList(issueHelper.globalClient)// populate issues here.
    }
    for(const i of images){
        await runImage(i)
    }
    // await images.map( async i => )
    await concatSarifs()
    await createHtmlOutput();

}


async function runImage(image:string){
    await runImageSarif(image)
    await runImageAudit(image)
    if (inputHelper.isRunIssueCreateEnabled()){
        await runImageIssue(image)
    }

    // await Promise.allSettled([runImageSarif(image),inputHelper.isRunIssueCreateEnabled() && runImageIssue(image), runImageAudit(image) ])
}

async function runImageSarif(image:string) {
    core.info(`Running SARIF Generation for the container ${image}`);
    const trivyResult = await trivyHelper.runTrivyTemplate(image,SARIFTemplate,trivyHelper.getTrivySarifOutputPath(image))
    if (trivyResult.status === trivyHelper.TRIVY_EXIT_CODE) {
        core.info(`Vulnerabilities were detected in the container ${image}`);
    } else if (trivyResult.status === 0) {
        core.info(`No vulnerabilities were detected in the container ${image}`);
    }else {
         utils.addLogsToError(trivyHelper.getTrivyLogPath(image));
    }
    core.info(`Completed SARIF Generation for the container ${image}`);
}
async function runImageAudit(image:string){
    core.info(`Running Audit Generation for the container ${image}`);
    const trivyResult = await trivyHelper.runTrivyTemplate(image,HTMLTableTemplate,trivyHelper.getTrivyHtmlOutputPath(image))
    if (trivyResult.status === trivyHelper.TRIVY_EXIT_CODE) {
        core.info(`Vulnerabilities were detected in the container ${image}`);
    } else if (trivyResult.status === 0) {
        core.info(`No vulnerabilities were detected in the container ${image}`);
    }else {
        utils.addLogsToError(trivyHelper.getTrivyLogPath(image));
    }
    core.info(`Completed Audit Generation for the container ${image}`);
}
async function runImageIssue(image:string){
    const trivyResult = await trivyHelper.runTrivy(image);

    if (trivyResult.status === trivyHelper.TRIVY_EXIT_CODE) {
        //create issues here?!
        const vulns = trivyHelper.getFilteredOutput(image);
        vulns.forEach(v => issueHelper.createIssueFromVuln(v,image))
    } else if (trivyResult.status === 0) {
        core.info("No vulnerabilities were detected in the container image");
    } else {
        utils.addLogsToError(trivyHelper.getTrivyLogPath(image));
    }
}

run().catch(error => core.setFailed(error.message));