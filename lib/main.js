"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.run = void 0;
const core = __importStar(require("@actions/core"));
// import * as dockleHelper from './dockleHelper';
const inputHelper = __importStar(require("./inputHelper"));
const allowedlistHandler = __importStar(require("./allowedlistHandler"));
const trivyHelper = __importStar(require("./trivyHelper"));
const utils = __importStar(require("./utils"));
const issueHelper = __importStar(require("./createIssue"));
const createIssue_1 = require("./createIssue");
// let issuesList = [];
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        inputHelper.validateRequiredInputs();
        allowedlistHandler.init();
        const images = inputHelper.imageNames.split(/\s|,/).filter(v => v !== ""); //white space or comma seperated. remove any empty ones also.
        yield issueHelper.getIssuesList(issueHelper.globalClient); // populate isssues here.
        yield Promise.allSettled(images.map(runImage));
        //TODO: create audit log output (configurable output location)
        //TODO: create a SARIF output for each image, concat - upload to Github Code Scanning
    });
}
exports.run = run;
function arrayToMDlist(arr) {
    let ret = "";
    if (arr === undefined || arr === null) {
        return ret;
    }
    arr.forEach(s => ret += `* [${s}](${s})\r\n`);
    return ret;
}
function createIssueFromVuln(vuln, imageName) {
    return __awaiter(this, void 0, void 0, function* () {
        const severities = trivyHelper.getSeveritiesToInclude();
        if (severities.includes(vuln.severity)) {
            //figure out labels
            const title = `${imageName} ${vuln.vulnerabilityId}`;
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
`;
            //Add in the no-fix label
            const labels = createIssue_1.SecurtiyLabels[vuln.severity];
            if (vuln.fixedVersion === undefined) {
                labels.push('no-fix');
            }
            const issue = {
                title,
                body,
                labels: labels,
            };
            yield issueHelper.createAnIssue(issueHelper.globalClient, issueHelper.issues, issue, vuln.fixedVersion);
        }
    });
}
function runImage(image) {
    return __awaiter(this, void 0, void 0, function* () {
        const trivyResult = yield trivyHelper.runTrivy(image);
        const trivyStatus = trivyResult.status;
        if (trivyStatus === trivyHelper.TRIVY_EXIT_CODE) {
            //create issues here?!
            const vulns = trivyHelper.getFilteredOutput();
            yield Promise.allSettled(vulns.map(v => createIssueFromVuln(v, image)));
            core.info(`Completed issue list for ${image}`);
            // vulns.forEach(v => createIssueFromVuln(v,image))
            //create a AUDIT entry for image.
        }
        else if (trivyStatus === 0) {
            core.info("No vulnerabilities were detected in the container image");
        }
        else {
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
    });
}
run().catch(error => core.setFailed(error.message));
