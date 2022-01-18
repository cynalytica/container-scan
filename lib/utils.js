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
exports.addLogsToDebug = exports.concatSarifs = exports.extractErrorsFromLogs = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const core = __importStar(require("@actions/core"));
const fileHelper = __importStar(require("./fileHelper"));
function extractErrorsFromLogs(outputPath, toolName) {
    const out = fs.readFileSync(outputPath, 'utf8');
    const lines = out.split('\n');
    let errors = [];
    lines.forEach((line) => {
        const errIndex = line.indexOf("FATAL");
        if (errIndex >= 0) {
            const err = line.substring(errIndex);
            errors.push(err);
        }
    });
    return errors;
}
exports.extractErrorsFromLogs = extractErrorsFromLogs;
function concatSarifs() {
    return __awaiter(this, void 0, void 0, function* () {
        const dir = fileHelper.getContainerScanDirectory();
        const sarifs = [];
        if (!fs.existsSync(dir)) {
            throw new Error("unable to find container scan directory");
        }
        const files = fs.readdirSync(dir);
        core.info(JSON.stringify(files));
        for (let i = 0; i < files.length; i++) {
            const filename = path.join(dir, files[i]);
            if (/\.sarif.json$/.test(filename))
                sarifs.push(fileHelper.getFileJson(filename));
        }
        const mainFile = sarifs[0];
        mainFile.runs = sarifs.map((sarif) => sarif.runs).reduce((cur, agg) => [...agg, ...cur]);
        fileHelper.writeFileJson(`${dir}/trivy.sarif.json`, mainFile);
        core.setOutput('sarif-report-path', `${dir}/trivy.sarif.json`);
    });
}
exports.concatSarifs = concatSarifs;
function addLogsToDebug(outputPath) {
    const out = fs.readFileSync(outputPath, 'utf8');
    core.debug(out);
}
exports.addLogsToDebug = addLogsToDebug;
