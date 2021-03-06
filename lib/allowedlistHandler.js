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
Object.defineProperty(exports, "__esModule", { value: true });
exports.init = exports.getTrivyAllowedlist = exports.trivyAllowedlistExists = void 0;
const fs = __importStar(require("fs"));
const jsyaml = __importStar(require("js-yaml"));
const fileHelper = __importStar(require("./fileHelper"));
let trivyAllowedlistPath = "";
exports.trivyAllowedlistExists = false;
function getTrivyAllowedlist() {
    if (exports.trivyAllowedlistExists)
        return trivyAllowedlistPath;
    else
        throw new Error("Could not find allowedlist file for common vulnerabilities");
}
exports.getTrivyAllowedlist = getTrivyAllowedlist;
function initializeTrivyAllowedlistPath() {
    trivyAllowedlistPath = `${fileHelper.getContainerScanDirectory()}/.trivyignore`;
}
function init() {
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
                exports.trivyAllowedlistExists = true;
                const vulnArray = allowedlistYaml.general.vulnerabilities;
                const trivyAllowedlistContent = vulnArray.join("\n");
                fs.writeFileSync(trivyAllowedlistPath, trivyAllowedlistContent);
            }
        }
    }
    catch (error) {
        throw new Error("Error while parsing allowedlist file. Error: " + error);
    }
}
exports.init = init;
