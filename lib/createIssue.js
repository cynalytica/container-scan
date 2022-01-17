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
const inputHelper = __importStar(require("./inputHelper"));
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
    [trivyHelper_1.SEVERITY_CRITICAL]: [dockerLabel, securityLabel, csastLabel + "1", trivyHelper_1.SEVERITY_CRITICAL.toLowerCase()],
    [trivyHelper_1.SEVERITY_HIGH]: [dockerLabel, securityLabel, csastLabel + "2", trivyHelper_1.SEVERITY_HIGH.toLowerCase()],
    [trivyHelper_1.SEVERITY_MEDIUM]: [dockerLabel, securityLabel, csastLabel + "2", trivyHelper_1.SEVERITY_MEDIUM.toLowerCase()],
    [trivyHelper_1.SEVERITY_LOW]: [dockerLabel, securityLabel, csastLabel + "3", trivyHelper_1.SEVERITY_LOW.toLowerCase()],
    [trivyHelper_1.SEVERITY_UNKNOWN]: [dockerLabel, securityLabel, csastLabel + "3", trivyHelper_1.SEVERITY_UNKNOWN.toLowerCase()],
};
//used to cache issues list
let issues = [];
function getIssuesList(client) {
    return __awaiter(this, void 0, void 0, function* () {
        if (issues.length == 0) {
            issues = yield client.paginate(client.rest.issues.listForRepo, Object.assign({}, github.context.repo));
        }
        return issues;
    });
}
function createIssue(client, issue) {
    return __awaiter(this, void 0, void 0, function* () {
        return yield client.rest.issues.create(Object.assign(Object.assign({}, github.context.repo), issue));
    });
}
function reopenIssue(client, issue_number) {
    return __awaiter(this, void 0, void 0, function* () {
        yield client.rest.issues.update(Object.assign(Object.assign({}, github.context.repo), { issue_number, state: 'open' }));
        yield client.rest.issues.createComment(Object.assign(Object.assign({}, github.context.repo), { issue_number, body: `CVE remains present in image, reopening issue. 
If this issue has already been applied please apply the \`${inputHelper.isFixedLabel}\` and close this issue again.` }));
    });
}
function removeLabelFromIssue(client, issue_number, name) {
    return __awaiter(this, void 0, void 0, function* () {
        yield client.rest.issues.removeLabel(Object.assign(Object.assign({}, github.context.repo), { issue_number, name }));
    });
}
function issueCanBeFixedNow(client, issue_number, fixedVersion) {
    return __awaiter(this, void 0, void 0, function* () {
        yield removeLabelFromIssue(client, issue_number, inputHelper.noFixYetLabel);
        yield client.rest.issues.createComment(Object.assign(Object.assign({}, github.context.repo), { issue_number, body: `A Fix can be found now by updating to version(s) ${fixedVersion}` }));
    });
}
function createAnIssue(issue, fixedVersion) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const client = github.getOctokit(inputHelper_1.githubToken);
            const issuesList = yield getIssuesList(client);
            const issueExists = issuesList.findIndex(({ title }) => title === issue.title);
            if (issueExists !== -1) {
                const { id, state, labels: issueLabels } = issuesList[issueExists];
                const hasWontFix = (issueLabels.findIndex(({ name }) => name === inputHelper.wontFixLabel) !== -1);
                const isFixed = (issueLabels.findIndex(({ name }) => name === inputHelper.isFixedLabel) !== -1);
                const cantFixLabel = (issueLabels.findIndex(({ name }) => name === inputHelper.noFixYetLabel) !== -1);
                if (state === "closed" && hasWontFix) {
                    core.debug(`issue has wont fix and is closed. doing nothing.`);
                }
                else if (state === "closed" && !hasWontFix && isFixed) {
                    core.debug(`issue has been fixed. doing nothing.`);
                }
                else if (state === "closed" && !hasWontFix && !isFixed) {
                    core.debug(`reopening issue. doing nothing.`);
                    yield reopenIssue(client, id);
                }
                else if (state === "open" && cantFixLabel && fixedVersion !== undefined) {
                    yield issueCanBeFixedNow(client, id, fixedVersion);
                }
            }
            else if (issueExists == -1) {
                core.debug(`new issue, creating ${issue.title}`);
                const newIssue = yield createIssue(client, issue);
                issues.push(newIssue); //prevent duplication from US
            }
        }
        catch (e) {
            core.error(e);
        }
    });
}
exports.createAnIssue = createAnIssue;
