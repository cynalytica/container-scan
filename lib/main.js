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
const inputHelper = __importStar(require("./inputHelper"));
const allowedlistHandler = __importStar(require("./allowedlistHandler"));
const trivyHelper = __importStar(require("./trivyHelper"));
const utils = __importStar(require("./utils"));
const issueHelper = __importStar(require("./createIssue"));
const utils_1 = require("./utils");
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        inputHelper.validateRequiredInputs();
        allowedlistHandler.init();
        yield trivyHelper.getTrivy(); //get trivy download first this will prevent multiple downloads.
        const images = inputHelper.imageNames.split(/\s|,/).filter(v => v !== ""); //white space or comma seperated. remove any empty ones also.
        yield issueHelper.getIssuesList(issueHelper.globalClient); // populate issues here.
        yield Promise.allSettled(images.map(runImageSarif));
        yield (0, utils_1.concatSarifs)();
        if (inputHelper.isRunIssueCreateEnabled()) {
            yield Promise.allSettled(images.map(runImage));
        }
        //TODO: create audit log output (configurable output location)
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
            const labels = issueHelper.SecurtiyLabels[vuln.severity];
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
function runImageSarif(image) {
    return __awaiter(this, void 0, void 0, function* () {
        const trivyResult = yield trivyHelper.runTrivySarif(image);
        const trivyStatus = trivyResult.status;
        if (trivyStatus === trivyHelper.TRIVY_EXIT_CODE) {
            const vulns = trivyHelper.getFilteredOutput(image);
            core.info(`Vulnerabilities were detected in the container ${image} ${vulns.length}`);
        }
        else if (trivyStatus === 0) {
            core.info(`No vulnerabilities were detected in the container ${image}`);
        }
    });
}
function runImage(image) {
    return __awaiter(this, void 0, void 0, function* () {
        const trivyResult = yield trivyHelper.runTrivy(image);
        const trivyStatus = trivyResult.status;
        if (trivyStatus === trivyHelper.TRIVY_EXIT_CODE) {
            //create issues here?!
            const vulns = trivyHelper.getFilteredOutput(image);
            vulns.forEach(v => createIssueFromVuln(v, image));
            // vulns.forEach(v => createIssueFromVuln(v,image))
            //create a AUDIT entry for image.
        }
        else if (trivyStatus === 0) {
            core.info("No vulnerabilities were detected in the container image");
        }
        else {
            const errors = utils.extractErrorsFromLogs(trivyHelper.getTrivyLogPath(image), trivyHelper.trivyToolName);
            errors.forEach(err => {
                core.error(err);
            });
            throw new Error(`An error occurred while scanning container image: ${image} for vulnerabilities.`);
        }
    });
}
run().catch(error => core.setFailed(error.message));
