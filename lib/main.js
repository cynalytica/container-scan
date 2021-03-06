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
const sarif_1 = require("./sarif/sarif");
const table_1 = require("./sarif/table");
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        inputHelper.validateRequiredInputs();
        allowedlistHandler.init();
        yield trivyHelper.getTrivy(); //get trivy download first this will prevent multiple downloads.
        const images = inputHelper.imageNames.split(/\s|,/).filter(v => v !== ""); //white space or comma seperated. remove any empty ones also.
        if (inputHelper.isRunIssueCreateEnabled()) {
            yield issueHelper.getIssuesList(issueHelper.globalClient); // populate issues here.
        }
        for (const i of images) {
            yield runImage(i);
        }
        // await images.map( async i => )
        yield (0, utils_1.concatSarifs)();
        yield (0, utils_1.createHtmlOutput)();
    });
}
exports.run = run;
function runImage(image) {
    return __awaiter(this, void 0, void 0, function* () {
        yield runImageSarif(image);
        yield runImageAudit(image);
        if (inputHelper.isRunIssueCreateEnabled()) {
            yield runImageIssue(image);
        }
        // await Promise.allSettled([runImageSarif(image),inputHelper.isRunIssueCreateEnabled() && runImageIssue(image), runImageAudit(image) ])
    });
}
function runImageSarif(image) {
    return __awaiter(this, void 0, void 0, function* () {
        core.info(`Running SARIF Generation for the container ${image}`);
        const trivyResult = yield trivyHelper.runTrivyTemplate(image, sarif_1.SARIFTemplate, trivyHelper.getTrivySarifOutputPath(image));
        if (trivyResult.status === trivyHelper.TRIVY_EXIT_CODE) {
            core.info(`Vulnerabilities were detected in the container ${image}`);
        }
        else if (trivyResult.status === 0) {
            core.info(`No vulnerabilities were detected in the container ${image}`);
        }
        else {
            utils.addLogsToError(trivyHelper.getTrivyLogPath(image));
        }
        core.info(`Completed SARIF Generation for the container ${image}`);
    });
}
function runImageAudit(image) {
    return __awaiter(this, void 0, void 0, function* () {
        core.info(`Running Audit Generation for the container ${image}`);
        const trivyResult = yield trivyHelper.runTrivyTemplate(image, table_1.HTMLTableTemplate, trivyHelper.getTrivyHtmlOutputPath(image));
        if (trivyResult.status === trivyHelper.TRIVY_EXIT_CODE) {
            core.info(`Vulnerabilities were detected in the container ${image}`);
        }
        else if (trivyResult.status === 0) {
            core.info(`No vulnerabilities were detected in the container ${image}`);
        }
        else {
            utils.addLogsToError(trivyHelper.getTrivyLogPath(image));
        }
        core.info(`Completed Audit Generation for the container ${image}`);
    });
}
function runImageIssue(image) {
    return __awaiter(this, void 0, void 0, function* () {
        const trivyResult = yield trivyHelper.runTrivy(image);
        if (trivyResult.status === trivyHelper.TRIVY_EXIT_CODE) {
            //create issues here?!
            const vulns = trivyHelper.getFilteredOutput(image);
            vulns.forEach(v => issueHelper.createIssueFromVuln(v, image));
        }
        else if (trivyResult.status === 0) {
            core.info("No vulnerabilities were detected in the container image");
        }
        else {
            utils.addLogsToError(trivyHelper.getTrivyLogPath(image));
        }
    });
}
run().catch(error => core.setFailed(error.message));
