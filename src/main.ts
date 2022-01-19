import * as core from '@actions/core';
import * as inputHelper from './inputHelper';
import * as allowedlistHandler from './allowedlistHandler';
import * as trivyHelper from './trivyHelper';
import * as utils from './utils';
import * as issueHelper from './createIssue'
import {concatSarifs, createHtmlOutput} from "./utils";
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
    const {status} = await trivyHelper.runTrivyTemplate(image,SARIFTemplate,trivyHelper.getTrivySarifOutputPath(image))
    if (status === trivyHelper.TRIVY_EXIT_CODE) {
        const vulns = trivyHelper.getFilteredOutput(image);
        core.info(`Vulnerabilities were detected in the container ${image} ${vulns.length}`);
    } else if (status === 0) {
        core.info(`No vulnerabilities were detected in the container ${image}`);
    }
    core.info(`Completed SARIF Generation for the container ${image}`);
}
async function runImageAudit(image:string){
    core.info(`Running Audit Generation for the container ${image}`);
    const {status} = await trivyHelper.runTrivyTemplate(image,HTMLTableTemplate,trivyHelper.getTrivyHtmlOutputPath(image))
    if (status === trivyHelper.TRIVY_EXIT_CODE) {
        core.info(`Vulnerabilities were detected in the container ${image}`);
    } else if (status === 0) {
        core.info(`No vulnerabilities were detected in the container ${image}`);
    }
    core.info(`Completed Audit Generation for the container ${image}`);
}
async function runImageIssue(image:string){
    const {status} = await trivyHelper.runTrivy(image);

    if (status === trivyHelper.TRIVY_EXIT_CODE) {
        //create issues here?!
        const vulns = trivyHelper.getFilteredOutput(image);
        vulns.forEach(v => issueHelper.createIssueFromVuln(v,image))
    } else if (status === 0) {
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