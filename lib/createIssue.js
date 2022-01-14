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
exports.createAnIssue = exports.SecurtiyLabels = exports.getSecurityLevel = exports.SecurityLevels = void 0;
const core = __importStar(require("@actions/core"));
const github = __importStar(require("@actions/github"));
const inputHelper_1 = require("./inputHelper");
const trivyHelper_1 = require("./trivyHelper");
const dockerLabel = "docker :whale:";
const securityLabel = "security :closed_lock_with_key:";
const csastLabel = "CSAT:";
exports.SecurityLevels = [trivyHelper_1.SEVERITY_UNKNOWN, trivyHelper_1.SEVERITY_LOW, trivyHelper_1.SEVERITY_MEDIUM, trivyHelper_1.SEVERITY_HIGH, trivyHelper_1.SEVERITY_CRITICAL];
function getSecurityLevel(level) {
    return exports.SecurityLevels.findIndex(lvl => lvl.toLowerCase() === level.toLowerCase());
}
exports.getSecurityLevel = getSecurityLevel;
exports.SecurtiyLabels = {
    SEVERITY_CRITICAL: [dockerLabel, securityLabel, csastLabel + "1", trivyHelper_1.SEVERITY_CRITICAL.toLowerCase()],
    SEVERITY_HIGH: [dockerLabel, securityLabel, csastLabel + "2", trivyHelper_1.SEVERITY_HIGH.toLowerCase()],
    SEVERITY_MEDIUM: [dockerLabel, securityLabel, csastLabel + "2", trivyHelper_1.SEVERITY_MEDIUM.toLowerCase()],
    SEVERITY_LOW: [dockerLabel, securityLabel, csastLabel + "3", trivyHelper_1.SEVERITY_LOW.toLowerCase()],
    SEVERITY_UNKNOWN: [dockerLabel, securityLabel, csastLabel + "3", trivyHelper_1.SEVERITY_UNKNOWN.toLowerCase()],
};
//used to cache issues list
let issues = [];
function getIssuesList(client) {
    return __awaiter(this, void 0, void 0, function* () {
        if (issues.length == 0) {
            issues = yield client.paginate(client.rest.issues.listForRepo, Object.assign(Object.assign({}, github.context.repo), { state: 'open' }));
        }
        return issues;
    });
}
function createAnIssue(issue) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            core.info(JSON.stringify(issue));
            const client = github.getOctokit(inputHelper_1.githubToken);
            const issuesList = yield getIssuesList(client);
            const issueExists = issuesList.findIndex(({ title }) => title == issue.title);
            if (issueExists == -1) {
                core.debug(`creating new issue ${issue.title}`);
                yield client.rest.issues.create(Object.assign(Object.assign({}, github.context.repo), issue));
                issues.push({ title: issue.title }); //prevent duplication from US
            }
        }
        catch (e) {
            core.error(e);
        }
    });
}
exports.createAnIssue = createAnIssue;
