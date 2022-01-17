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
exports.validateRequiredInputs = exports.isRunQualityChecksEnabled = exports.runQualityChecks = exports.severityThreshold = exports.password = exports.username = exports.githubToken = exports.isFixedLabel = exports.noFixYetLabel = exports.wontFixLabel = exports.imageNames = void 0;
const core = __importStar(require("@actions/core"));
exports.imageNames = core.getInput("image-names");
exports.wontFixLabel = core.getInput("wont-fix-label");
exports.noFixYetLabel = core.getInput("no-fix-label");
exports.isFixedLabel = core.getInput("is-fixed-label");
exports.githubToken = core.getInput("token");
exports.username = core.getInput("username");
exports.password = core.getInput("password");
exports.severityThreshold = core.getInput("severity-threshold");
exports.runQualityChecks = core.getInput("run-quality-checks");
function isRunQualityChecksEnabled() {
    return exports.runQualityChecks.toLowerCase() === "true";
}
exports.isRunQualityChecksEnabled = isRunQualityChecksEnabled;
function validateRequiredInputs() {
    if (!exports.wontFixLabel)
        throw new Error("'wont-fix-label' input is not supplied. Provide a label to use");
    if (!exports.noFixYetLabel)
        throw new Error("'no-fix-label' input is not supplied. Provide a label to use");
    if (!exports.isFixedLabel)
        throw new Error("'is-fixed-label' input is not supplied. Provide a label to use");
    if (!exports.githubToken)
        throw new Error("'token' input is not supplied. Set it to a PAT/GITHUB_TOKEN");
}
exports.validateRequiredInputs = validateRequiredInputs;
