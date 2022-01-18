import * as fs from 'fs';
import * as jsyaml from 'js-yaml';
import * as fileHelper from './fileHelper';

let trivyAllowedlistPath = "";
export let trivyAllowedlistExists = false;

export function getTrivyAllowedlist(): string {
    if (trivyAllowedlistExists)
        return trivyAllowedlistPath;
    else
        throw new Error("Could not find allowedlist file for common vulnerabilities");
}

function initializeTrivyAllowedlistPath() {
    trivyAllowedlistPath = `${fileHelper.getContainerScanDirectory()}/.trivyignore`;
}


export function init() {
    let allowedlistFilePath = `${process.env['GITHUB_WORKSPACE']}/.github/containerscan/allowedlist.yaml`;
    if (!fs.existsSync(allowedlistFilePath)) {
        allowedlistFilePath = `${process.env['GITHUB_WORKSPACE']}/.github/containerscan/allowedlist.yml`;
        if (!fs.existsSync(allowedlistFilePath)) {
            console.log("Could not find allowedlist file.");
            return;
        }
    }

    initializeTrivyAllowedlistPath();

    try {
        const allowedlistYaml = jsyaml.load(fs.readFileSync(allowedlistFilePath, 'utf8'));
        if (allowedlistYaml.general) {
            if (allowedlistYaml.general.vulnerabilities) {
                trivyAllowedlistExists = true;
                const vulnArray: string[] = allowedlistYaml.general.vulnerabilities;
                const trivyAllowedlistContent = vulnArray.join("\n");
                fs.writeFileSync(trivyAllowedlistPath, trivyAllowedlistContent);
            }
        }
    } catch (error) {
        throw new Error("Error while parsing allowedlist file. Error: " + error);
    }
}