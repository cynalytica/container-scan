import * as os from 'os';
import * as util from 'util';
import * as fs from 'fs';
import * as toolCache from '@actions/tool-cache';
import * as core from '@actions/core';
import * as semver from 'semver';
import { ExecOptions } from '@actions/exec/lib/interfaces';
import { ToolRunner } from '@actions/exec/lib/toolrunner';
import * as fileHelper from './fileHelper';
import * as inputHelper from './inputHelper';
import * as utils from './utils';
import * as allowedlistHandler from './allowedlistHandler';
import {SARIFTemplate} from "./sarif/sarif";

export const TRIVY_EXIT_CODE = 5;
export const trivyToolName = "trivy";
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
const KEY_TITLE = "Title" //GH title = Image Name + CVE_NAME



const KEY_DESCRIPTION = "Description";
export const SEVERITY_CRITICAL = "CRITICAL";
export const SEVERITY_HIGH = "HIGH";
export const SEVERITY_MEDIUM = "MEDIUM";
export const SEVERITY_LOW = "LOW";
export const SEVERITY_UNKNOWN = "UNKNOWN";



export interface TrivyResult {
    status: number;
    timestamp: string;
};


export async function runTrivyTemplate(imageName:string,template:string, outputPath:string): Promise<TrivyResult> {
    let trivyResult: TrivyResult;
    try {

        const trivyPath = await getTrivy();
        const trivyOptions: ExecOptions = await getTrivyExecOptionsTemplate(imageName,template,outputPath);
        const trivyToolRunner = new ToolRunner(trivyPath, ["image",imageName ], trivyOptions);
        const timestamp = new Date().toISOString();
        const trivyStatus = await trivyToolRunner.exec();
        utils.addLogsToDebug(getTrivyLogPath(imageName));
        trivyResult = {
            status: trivyStatus,
            timestamp: timestamp
        };
    }catch (e) {
        core.error(e)
    }
    return trivyResult;
}

export async function runTrivy(imageName:string = ""): Promise<TrivyResult> {
    let trivyResult: TrivyResult;
    try {


        const trivyPath = await getTrivy();
        // const imageName = inputHelper.imageName;
        const trivyOptions: ExecOptions = await getTrivyExecOptions(imageName);
        core.info(`Scanning for vulnerabilities in image: ${imageName}`);
        const trivyToolRunner = new ToolRunner(trivyPath, ["image",imageName], trivyOptions);
        const timestamp = new Date().toISOString();
        const trivyStatus = await trivyToolRunner.exec();
        utils.addLogsToDebug(getTrivyLogPath(imageName));
        trivyResult = {
            status: trivyStatus,
            timestamp: timestamp
        };
    }catch (e) {
        core.error(e)
    }
    return trivyResult;
}

export async function getTrivy(): Promise<string> {
    const latestTrivyVersion = await getLatestTrivyVersion();

    let cachedToolPath = toolCache.find(trivyToolName, latestTrivyVersion);
    if (!cachedToolPath) {
        let trivyDownloadPath;
        const trivyDownloadUrl = getTrivyDownloadUrl(latestTrivyVersion);
        const trivyDownloadDir = `${process.env['GITHUB_WORKSPACE']}/_temp/tools/trivy`;
        core.debug(util.format("Could not find trivy in cache, downloading from %s", trivyDownloadUrl));

        try {
            trivyDownloadPath = await toolCache.downloadTool(trivyDownloadUrl, trivyDownloadDir);
        } catch (error) {
            throw new Error(util.format("Failed to download trivy from %s: %s", trivyDownloadUrl, error.toString()));
        }

        const untarredTrivyPath = await toolCache.extractTar(trivyDownloadPath);
        cachedToolPath = await toolCache.cacheDir(untarredTrivyPath, trivyToolName, latestTrivyVersion);
    }

    const trivyToolPath = cachedToolPath + "/" + trivyToolName;
    fs.chmodSync(trivyToolPath, "777");

    core.debug(util.format("Trivy executable found at path ", trivyToolPath));
    return trivyToolPath;
}

export function getOutputPath(image:string): string {
    //image name format = group/name:version
    //lets take the name:version as the output
    const reReplace = /[\/:.]/g;
    const iName = image.replace(reReplace,"_");
    return `${fileHelper.getContainerScanDirectory()}/${iName}_trivyoutput.json`;
}

export function getTrivyLogPath(image:string): string {
    const reReplace = /[\/:.]/g;
    const iName = image.replace(reReplace,"_");
    return `${fileHelper.getContainerScanDirectory()}/${iName}_trivylog`;
}

export function getTrivySarifOutputPath(image:string): string {
    const reReplace = /[\/:.]/g;
    const iName = image.replace(reReplace,"_");
    return `${fileHelper.getContainerScanDirectory()}/${iName}.sarif.json`;
}
export function getTrivyHtmlOutputPath(image:string): string {
    const reReplace = /[\/:.]/g;
    const iName = image.replace(reReplace,"_");
    return `${fileHelper.getContainerScanDirectory()}/${iName}.html`;
}


export function getSeveritiesToInclude(warnIfInvalid?: boolean): string[] {
    let severities: string[] = [];
    const severityThreshold = inputHelper.severityThreshold;
    if (severityThreshold) {
        switch (severityThreshold.toUpperCase()) {
            case SEVERITY_UNKNOWN:
                severities = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_UNKNOWN];
                break;
            case SEVERITY_LOW:
                severities = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW];
                break;
            case SEVERITY_MEDIUM:
                severities = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM];
                break;
            case SEVERITY_HIGH:
                severities = [SEVERITY_CRITICAL, SEVERITY_HIGH];
                break;
            case SEVERITY_CRITICAL:
                severities = [SEVERITY_CRITICAL];
                break;
            default:
                if (warnIfInvalid) {
                    core.warning("Invalid severity-threshold. Showing all the vulnerabilities.");
                }
                severities = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_UNKNOWN];
        }
    } else {
        if (warnIfInvalid) {
            core.warning("No severity-threshold provided. Showing all the vulnerabilities.");
        }
        severities = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_UNKNOWN];
    }

    return severities;
}

export interface FilterOutput {
    title: string
    description: string
    vulnerabilityId: string
    packageName: string
    severity: string
    severitySource: string
    version: string
    fixedVersion: string
    target: string
    references: string[]

}

export function getFilteredOutput(image:string):FilterOutput[] {
    const vulnerabilities = getVulnerabilities(image);
    return vulnerabilities.map((cve: any) => (
        {
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
        }))
}

async function getTrivyEnvVariables(image:string): Promise<{ [key: string]: string }> {
    let trivyEnv: { [key: string]: string } = {};
    for (let key in process.env) {
        trivyEnv[key] = process.env[key] || "";
    }

    const username = inputHelper.username;
    const password = inputHelper.password;
    if (username && password) {
        trivyEnv["TRIVY_USERNAME"] = username;
        trivyEnv["TRIVY_PASSWORD"] = password;
    }

    trivyEnv["TRIVY_EXIT_CODE"] = TRIVY_EXIT_CODE.toString();
    trivyEnv["TRIVY_FORMAT"] = "json";
    trivyEnv["TRIVY_OUTPUT"] = getOutputPath(image);
    trivyEnv["GITHUB_TOKEN"] = inputHelper.githubToken;

    if (allowedlistHandler.trivyAllowedlistExists) {
        trivyEnv["TRIVY_IGNOREFILE"] = allowedlistHandler.getTrivyAllowedlist();
    }

    const severities = getSeveritiesToInclude(true);
    trivyEnv["TRIVY_SEVERITY"] = severities.join(',');

    return trivyEnv;
}


async function getTrivyEnvVariablesTemplate(image:string, template:string,outputPath:string): Promise<{ [key: string]: string }> {
    let trivyEnv: { [key: string]: string } = {};
    for (let key in process.env) {
        trivyEnv[key] = process.env[key] || "";
    }

    const username = inputHelper.username;
    const password = inputHelper.password;
    if (username && password) {
        trivyEnv["TRIVY_USERNAME"] = username;
        trivyEnv["TRIVY_PASSWORD"] = password;
    }

    trivyEnv["TRIVY_EXIT_CODE"] = TRIVY_EXIT_CODE.toString();
    trivyEnv["TRIVY_FORMAT"] = 'template';
    trivyEnv["TRIVY_TEMPLATE"] = template
    trivyEnv["TRIVY_OUTPUT"] = outputPath; //getTrivySarifOutputPath(image);
    trivyEnv["GITHUB_TOKEN"] = inputHelper.githubToken;

    if (allowedlistHandler.trivyAllowedlistExists) {
        trivyEnv["TRIVY_IGNOREFILE"] = allowedlistHandler.getTrivyAllowedlist();
    }

    const severities = getSeveritiesToInclude(true);
    trivyEnv["TRIVY_SEVERITY"] = severities.join(',');

    return trivyEnv;
}

function getTrivyOutput(image:string): any {
    const path = getOutputPath(image);
    return fileHelper.getFileJson(path);
}

function isOldTrivyJson(trivyOutputJson: any): boolean {
    return Array.isArray(trivyOutputJson);
}

function getTrivyResult(trivyOutputJson: any): any {
    return isOldTrivyJson(trivyOutputJson)
        ? trivyOutputJson
        : trivyOutputJson["Results"];
}

function getVulnerabilities(image:string, removeDuplicates?: boolean): any[] {
    const trivyOutputJson = getTrivyOutput(image);
    let vulnerabilities: any[] = [];
    const trivyResult = getTrivyResult(trivyOutputJson);
    trivyResult.forEach((ele: any) => {
        if (ele && ele[KEY_VULNERABILITIES]) {
            let target = ele[KEY_TARGET];
            ele[KEY_VULNERABILITIES].forEach((cve: any) => {
                if (!removeDuplicates || !vulnerabilities.some(v => v[KEY_VULNERABILITY_ID] === cve[KEY_VULNERABILITY_ID])) {
                    cve[KEY_TARGET] = target;
                    vulnerabilities.push(cve);
                }
            });
        }
    });

    return vulnerabilities;
}

async function getLatestTrivyVersion(): Promise<string> {
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
}

function getTrivyDownloadUrl(trivyVersion: string): string {
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

async function getTrivyExecOptions(image: string) {
    const trivyEnv = await getTrivyEnvVariables(image);
    return {
        env: trivyEnv,
        ignoreReturnCode: true,
        outStream: fs.createWriteStream(getTrivyLogPath(image))
    };
}
async function getTrivyExecOptionsTemplate(image: string, template:string, outputPath:string) {
    const trivyEnv = await getTrivyEnvVariablesTemplate(image,template,outputPath);
    return {
        env: trivyEnv,
        ignoreReturnCode: true,
        outStream: fs.createWriteStream(getTrivyLogPath(image))
    };
}