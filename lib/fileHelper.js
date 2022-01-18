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
exports.getContainerScanDirectory = exports.writeFileJson = exports.getFileJson = void 0;
const fs = __importStar(require("fs"));
let CONTAINER_SCAN_DIRECTORY = '';
function getFileJson(path) {
    try {
        const rawContent = fs.readFileSync(path, 'utf-8');
        return JSON.parse(rawContent);
    }
    catch (ex) {
        throw new Error(`An error occurred while parsing the contents of the file: ${path}. Error: ${ex}`);
    }
}
exports.getFileJson = getFileJson;
function writeFileJson(path, json) {
    try {
        fs.writeFileSync(path, JSON.stringify(json));
    }
    catch (ex) {
        throw new Error(`An error occurred while writing the contents of the file: ${path}. Error: ${ex}`);
    }
}
exports.writeFileJson = writeFileJson;
function getContainerScanDirectory() {
    if (!CONTAINER_SCAN_DIRECTORY) {
        CONTAINER_SCAN_DIRECTORY = `${process.env['GITHUB_WORKSPACE']}/_temp/containerscan}`;
        ensureDirExists(CONTAINER_SCAN_DIRECTORY);
    }
    return CONTAINER_SCAN_DIRECTORY;
}
exports.getContainerScanDirectory = getContainerScanDirectory;
function ensureDirExists(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}
