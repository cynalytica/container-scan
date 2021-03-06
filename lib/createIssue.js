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
exports.createAnIssue = exports.getIssuesList = exports.issues = exports.SecurtiyLabels = exports.getSecurityLevel = exports.SecurityLevels = exports.createIssueFromVuln = exports.globalClient = void 0;
const core = __importStar(require("@actions/core"));
const github = __importStar(require("./client/github"));
const inputHelper = __importStar(require("./inputHelper"));
const trivyHelper_1 = require("./trivyHelper");
const trivyHelper = __importStar(require("./trivyHelper"));
exports.globalClient = github.getOctokit(inputHelper.githubToken, { throttle: {
        onRateLimit: (retryAfter, options) => {
            core.warning(`Request quota exhausted for request ${options.method} ${options.url}`);
            if (options.request.retyCount <= parseInt(inputHelper.maxCreationRetryCount, 10)) {
                return true;
            }
            core.info(`Retrying after ${retryAfter} seconds!`);
            return true;
        },
        onAbuseLimit: (retryAfter, options) => {
            // does not retry, only logs a warning
            if (options.request.retyCount <= parseInt(inputHelper.maxCreationRetryCount, 10)) {
                return true;
            }
            core.warning(`Abuse detected for request ${options.method} ${options.url}. Retrying after ${retryAfter} seconds!`);
        },
    } });
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
            const labels = exports.SecurtiyLabels[vuln.severity];
            if (vuln.fixedVersion === undefined) {
                labels.push('no-fix');
            }
            const issue = {
                title,
                body,
                labels: labels,
            };
            yield createAnIssue(exports.globalClient, exports.issues, issue, vuln.fixedVersion);
        }
    });
}
exports.createIssueFromVuln = createIssueFromVuln;
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
exports.issues = [];
function getIssuesList(client) {
    return __awaiter(this, void 0, void 0, function* () {
        if (exports.issues.length == 0) {
            exports.issues = yield client.paginate(client.rest.issues.listForRepo, Object.assign(Object.assign({}, github.context.repo), { state: 'all' }));
        }
        return exports.issues;
    });
}
exports.getIssuesList = getIssuesList;
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
        try {
            yield client.rest.issues.removeLabel(Object.assign(Object.assign({}, github.context.repo), { issue_number, name }));
        }
        catch (e) {
            core.error(`removeLabelFromIssue:${issue_number},${name}, ${e}`);
        }
    });
}
function issueCanBeFixedNow(client, issue_number, fixedVersion, state) {
    return __awaiter(this, void 0, void 0, function* () {
        if (state === 'closed') {
            try {
                yield client.rest.issues.update(Object.assign(Object.assign({}, github.context.repo), { issue_number, state: 'open' }));
            }
            catch (e) {
                core.error(`reopenIssue: ${e}`);
            }
        }
        yield removeLabelFromIssue(client, issue_number, inputHelper.noFixYetLabel);
        try {
            yield client.rest.issues.createComment(Object.assign(Object.assign({}, github.context.repo), { issue_number, body: `A Fix can be found now by updating to version(s) ${fixedVersion}` }));
        }
        catch (e) {
            core.error(`createComment:${issue_number}, ${e}`);
        }
    });
}
function createAnIssue(client, issuesList, issue, fixedVersion) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const issueExists = issuesList.findIndex(({ title }) => title === issue.title);
            if (issueExists !== -1) {
                const { number: id, state, labels: issueLabels } = issuesList[issueExists];
                const hasWontFix = (issueLabels.findIndex(({ name }) => name === inputHelper.wontFixLabel) !== -1);
                const isFixed = (issueLabels.findIndex(({ name }) => name === inputHelper.isFixedLabel) !== -1);
                const cantFixLabel = (issueLabels.findIndex(({ name }) => name === inputHelper.noFixYetLabel) !== -1);
                if (state === "closed" && !hasWontFix && !isFixed && !cantFixLabel) {
                    core.info(`Issue is not fixed, and can be fixed reopening issue.`);
                    yield reopenIssue(client, id);
                }
                else if (cantFixLabel && fixedVersion !== undefined) {
                    core.info(`Fix has been found. Updating issue`);
                    yield issueCanBeFixedNow(client, id, fixedVersion, state);
                }
                else {
                    core.info(`${id} => ${state} wontFix:${hasWontFix} isFixed:${isFixed} noFix:${cantFixLabel}`);
                }
            }
            else if (issueExists == -1) {
                core.debug(`new issue, creating ${issue.title}`);
                const newIssue = yield createIssue(client, issue);
                exports.issues.push(Object.assign(Object.assign({}, newIssue), { title: issue.title })); //prevent duplication from US
            }
        }
        catch (e) {
            core.error(e);
        }
    });
}
exports.createAnIssue = createAnIssue;
