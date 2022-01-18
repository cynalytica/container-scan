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
exports.getFilteredOutput = exports.getSeveritiesToInclude = exports.getTrivySarifOutputPath = exports.getTrivyLogPath = exports.getOutputPath = exports.getTrivy = exports.runTrivy = exports.runTrivySarif = exports.SEVERITY_UNKNOWN = exports.SEVERITY_LOW = exports.SEVERITY_MEDIUM = exports.SEVERITY_HIGH = exports.SEVERITY_CRITICAL = exports.trivyToolName = exports.TRIVY_EXIT_CODE = void 0;
const os = __importStar(require("os"));
const util = __importStar(require("util"));
const fs = __importStar(require("fs"));
const toolCache = __importStar(require("@actions/tool-cache"));
const core = __importStar(require("@actions/core"));
const semver = __importStar(require("semver"));
const toolrunner_1 = require("@actions/exec/lib/toolrunner");
const fileHelper = __importStar(require("./fileHelper"));
const inputHelper = __importStar(require("./inputHelper"));
const utils = __importStar(require("./utils"));
const allowedlistHandler = __importStar(require("./allowedlistHandler"));
const sarif_1 = require("./sarif/sarif");
exports.TRIVY_EXIT_CODE = 5;
exports.trivyToolName = "trivy";
const stableTrivyVersion = "0.5.2";
const trivyLatestReleaseUrl = "https://api.github.com/repos/aquasecurity/trivy/releases/latest";
const KEY_TARGET = "Target";
const KEY_VULNERABILITIES = "Vulnerabilities";
const KEY_VULNERABILITY_ID = "VulnerabilityID";
const KEY_VERSION = "InstalledVersion";
const KEY_FIXED_VERSION = "FixedVersion";
const KEY_REFS = "References";
const KEY_PACKAGE_NAME = "PkgName";
const KEY_SEVERITY_SOURCE = "SeveritySource";
const KEY_SEVERITY = "Severity";
const KEY_TITLE = "Title"; //GH title = Image Name + CVE_NAME
const KEY_DESCRIPTION = "Description";
exports.SEVERITY_CRITICAL = "CRITICAL";
exports.SEVERITY_HIGH = "HIGH";
exports.SEVERITY_MEDIUM = "MEDIUM";
exports.SEVERITY_LOW = "LOW";
exports.SEVERITY_UNKNOWN = "UNKNOWN";
;
function runTrivySarif(imageName) {
    return __awaiter(this, void 0, void 0, function* () {
        let trivyResult;
        try {
            const trivyPath = yield getTrivy();
            const trivyOptions = yield getTrivyExecOptionsSarif(imageName);
            const trivyToolRunner = new toolrunner_1.ToolRunner(trivyPath, ["image", imageName], trivyOptions);
            const timestamp = new Date().toISOString();
            const trivyStatus = yield trivyToolRunner.exec();
            utils.addLogsToDebug(getTrivyLogPath(imageName));
            trivyResult = {
                status: trivyStatus,
                timestamp: timestamp
            };
        }
        catch (e) {
            core.error(e);
        }
        return trivyResult;
    });
}
exports.runTrivySarif = runTrivySarif;
function runTrivy(imageName = "") {
    return __awaiter(this, void 0, void 0, function* () {
        let trivyResult;
        try {
            const trivyPath = yield getTrivy();
            // const imageName = inputHelper.imageName;
            const trivyOptions = yield getTrivyExecOptions(imageName);
            core.info(`Scanning for vulnerabilities in image: ${imageName}`);
            const trivyToolRunner = new toolrunner_1.ToolRunner(trivyPath, ["image", imageName], trivyOptions);
            const timestamp = new Date().toISOString();
            const trivyStatus = yield trivyToolRunner.exec();
            utils.addLogsToDebug(getTrivyLogPath(imageName));
            trivyResult = {
                status: trivyStatus,
                timestamp: timestamp
            };
        }
        catch (e) {
            core.error(e);
        }
        return trivyResult;
    });
}
exports.runTrivy = runTrivy;
function getTrivy() {
    return __awaiter(this, void 0, void 0, function* () {
        const latestTrivyVersion = yield getLatestTrivyVersion();
        let cachedToolPath = toolCache.find(exports.trivyToolName, latestTrivyVersion);
        if (!cachedToolPath) {
            let trivyDownloadPath;
            const trivyDownloadUrl = getTrivyDownloadUrl(latestTrivyVersion);
            const trivyDownloadDir = `${process.env['GITHUB_WORKSPACE']}/_temp/tools/trivy`;
            core.debug(util.format("Could not find trivy in cache, downloading from %s", trivyDownloadUrl));
            try {
                trivyDownloadPath = yield toolCache.downloadTool(trivyDownloadUrl, trivyDownloadDir);
            }
            catch (error) {
                throw new Error(util.format("Failed to download trivy from %s: %s", trivyDownloadUrl, error.toString()));
            }
            const untarredTrivyPath = yield toolCache.extractTar(trivyDownloadPath);
            cachedToolPath = yield toolCache.cacheDir(untarredTrivyPath, exports.trivyToolName, latestTrivyVersion);
        }
        const trivyToolPath = cachedToolPath + "/" + exports.trivyToolName;
        fs.chmodSync(trivyToolPath, "777");
        core.debug(util.format("Trivy executable found at path ", trivyToolPath));
        return trivyToolPath;
    });
}
exports.getTrivy = getTrivy;
function getOutputPath(image) {
    //image name format = group/name:version
    //lets take the name:version as the output
    const reReplace = /[\/:]/g;
    const iName = image.replace(reReplace, "_");
    return `${fileHelper.getContainerScanDirectory()}/${iName}_trivyoutput.json`;
}
exports.getOutputPath = getOutputPath;
function getTrivyLogPath(image) {
    const reReplace = /[\/:]/g;
    const iName = image.replace(reReplace, "_");
    return `${fileHelper.getContainerScanDirectory()}/${iName}_trivylog`;
}
exports.getTrivyLogPath = getTrivyLogPath;
function getTrivySarifOutputPath(image) {
    const reReplace = /[\/:]/g;
    const iName = image.replace(reReplace, "_");
    return `${fileHelper.getContainerScanDirectory()}/${iName}.sarif.json`;
}
exports.getTrivySarifOutputPath = getTrivySarifOutputPath;
function getSeveritiesToInclude(warnIfInvalid) {
    let severities = [];
    const severityThreshold = inputHelper.severityThreshold;
    if (severityThreshold) {
        switch (severityThreshold.toUpperCase()) {
            case exports.SEVERITY_UNKNOWN:
                severities = [exports.SEVERITY_CRITICAL, exports.SEVERITY_HIGH, exports.SEVERITY_MEDIUM, exports.SEVERITY_LOW, exports.SEVERITY_UNKNOWN];
                break;
            case exports.SEVERITY_LOW:
                severities = [exports.SEVERITY_CRITICAL, exports.SEVERITY_HIGH, exports.SEVERITY_MEDIUM, exports.SEVERITY_LOW];
                break;
            case exports.SEVERITY_MEDIUM:
                severities = [exports.SEVERITY_CRITICAL, exports.SEVERITY_HIGH, exports.SEVERITY_MEDIUM];
                break;
            case exports.SEVERITY_HIGH:
                severities = [exports.SEVERITY_CRITICAL, exports.SEVERITY_HIGH];
                break;
            case exports.SEVERITY_CRITICAL:
                severities = [exports.SEVERITY_CRITICAL];
                break;
            default:
                if (warnIfInvalid) {
                    core.warning("Invalid severity-threshold. Showing all the vulnerabilities.");
                }
                severities = [exports.SEVERITY_CRITICAL, exports.SEVERITY_HIGH, exports.SEVERITY_MEDIUM, exports.SEVERITY_LOW, exports.SEVERITY_UNKNOWN];
        }
    }
    else {
        if (warnIfInvalid) {
            core.warning("No severity-threshold provided. Showing all the vulnerabilities.");
        }
        severities = [exports.SEVERITY_CRITICAL, exports.SEVERITY_HIGH, exports.SEVERITY_MEDIUM, exports.SEVERITY_LOW, exports.SEVERITY_UNKNOWN];
    }
    return severities;
}
exports.getSeveritiesToInclude = getSeveritiesToInclude;
function getFilteredOutput(image) {
    const vulnerabilities = getVulnerabilities(image);
    return vulnerabilities.map((cve) => ({
        title: cve[KEY_TITLE],
        "description": cve[KEY_DESCRIPTION],
        "vulnerabilityId": cve[KEY_VULNERABILITY_ID],
        "packageName": cve[KEY_PACKAGE_NAME],
        "severity": cve[KEY_SEVERITY],
        "severitySource": cve[KEY_SEVERITY_SOURCE],
        "version": cve[KEY_VERSION],
        "fixedVersion": cve[KEY_FIXED_VERSION],
        "target": cve[KEY_TARGET],
        "references": cve[KEY_REFS]
    }));
}
exports.getFilteredOutput = getFilteredOutput;
function getTrivyEnvVariables(image) {
    return __awaiter(this, void 0, void 0, function* () {
        let trivyEnv = {};
        for (let key in process.env) {
            trivyEnv[key] = process.env[key] || "";
        }
        const username = inputHelper.username;
        const password = inputHelper.password;
        if (username && password) {
            trivyEnv["TRIVY_USERNAME"] = username;
            trivyEnv["TRIVY_PASSWORD"] = password;
        }
        trivyEnv["TRIVY_EXIT_CODE"] = exports.TRIVY_EXIT_CODE.toString();
        trivyEnv["TRIVY_FORMAT"] = "json";
        trivyEnv["TRIVY_OUTPUT"] = getOutputPath(image);
        trivyEnv["GITHUB_TOKEN"] = inputHelper.githubToken;
        if (allowedlistHandler.trivyAllowedlistExists) {
            trivyEnv["TRIVY_IGNOREFILE"] = allowedlistHandler.getTrivyAllowedlist();
        }
        const severities = getSeveritiesToInclude(true);
        trivyEnv["TRIVY_SEVERITY"] = severities.join(',');
        return trivyEnv;
    });
}
function getTrivyEnvVariablesSarif(image) {
    return __awaiter(this, void 0, void 0, function* () {
        let trivyEnv = {};
        for (let key in process.env) {
            trivyEnv[key] = process.env[key] || "";
        }
        const username = inputHelper.username;
        const password = inputHelper.password;
        if (username && password) {
            trivyEnv["TRIVY_USERNAME"] = username;
            trivyEnv["TRIVY_PASSWORD"] = password;
        }
        trivyEnv["TRIVY_EXIT_CODE"] = exports.TRIVY_EXIT_CODE.toString();
        trivyEnv["TRIVY_FORMAT"] = 'template';
        trivyEnv["TRIVY_TEMPLATE"] = sarif_1.SARIFTemplate;
        trivyEnv["TRIVY_OUTPUT"] = getTrivySarifOutputPath(image);
        trivyEnv["GITHUB_TOKEN"] = inputHelper.githubToken;
        if (allowedlistHandler.trivyAllowedlistExists) {
            trivyEnv["TRIVY_IGNOREFILE"] = allowedlistHandler.getTrivyAllowedlist();
        }
        const severities = getSeveritiesToInclude(true);
        trivyEnv["TRIVY_SEVERITY"] = severities.join(',');
        return trivyEnv;
    });
}
function getTrivyOutput(image) {
    const path = getOutputPath(image);
    return fileHelper.getFileJson(path);
}
function isOldTrivyJson(trivyOutputJson) {
    return Array.isArray(trivyOutputJson);
}
function getTrivyResult(trivyOutputJson) {
    return isOldTrivyJson(trivyOutputJson)
        ? trivyOutputJson
        : trivyOutputJson["Results"];
}
function getVulnerabilities(image, removeDuplicates) {
    const trivyOutputJson = getTrivyOutput(image);
    let vulnerabilities = [];
    const trivyResult = getTrivyResult(trivyOutputJson);
    trivyResult.forEach((ele) => {
        if (ele && ele[KEY_VULNERABILITIES]) {
            let target = ele[KEY_TARGET];
            ele[KEY_VULNERABILITIES].forEach((cve) => {
                if (!removeDuplicates || !vulnerabilities.some(v => v[KEY_VULNERABILITY_ID] === cve[KEY_VULNERABILITY_ID])) {
                    cve[KEY_TARGET] = target;
                    vulnerabilities.push(cve);
                }
            });
        }
    });
    return vulnerabilities;
}
function getLatestTrivyVersion() {
    return __awaiter(this, void 0, void 0, function* () {
        return toolCache.downloadTool(trivyLatestReleaseUrl).then((downloadPath) => {
            const response = JSON.parse(fs.readFileSync(downloadPath, 'utf8').toString().trim());
            if (!response.tag_name) {
                return stableTrivyVersion;
            }
            return semver.clean(response.tag_name);
        }, (error) => {
            core.warning(util.format("Failed to read latest trivy verison from %s. Using default stable version %s", trivyLatestReleaseUrl, stableTrivyVersion));
            return stableTrivyVersion;
        });
    });
}
function getTrivyDownloadUrl(trivyVersion) {
    const curOS = os.type();
    switch (curOS) {
        case "Linux":
            return util.format("https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_Linux-64bit.tar.gz", trivyVersion, trivyVersion);
        case "Darwin":
            return util.format("https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_macOS-64bit.tar.gz", trivyVersion, trivyVersion);
        default:
            throw new Error(util.format("Container scanning is not supported on %s currently", curOS));
    }
}
function getTrivyExecOptions(image) {
    return __awaiter(this, void 0, void 0, function* () {
        const trivyEnv = yield getTrivyEnvVariables(image);
        return {
            env: trivyEnv,
            ignoreReturnCode: true,
            outStream: fs.createWriteStream(getTrivyLogPath(image))
        };
    });
}
function getTrivyExecOptionsSarif(image) {
    return __awaiter(this, void 0, void 0, function* () {
        const trivyEnv = yield getTrivyEnvVariablesSarif(image);
        return {
            env: trivyEnv,
            ignoreReturnCode: true,
            outStream: fs.createWriteStream(getTrivyLogPath(image))
        };
    });
}
