import * as core from '@actions/core';

export const imageNames = core.getInput("image-names");
export const wontFixLabel = core.getInput("wont-fix-label");
export const noFixYetLabel = core.getInput("no-fix-label");
export const isFixedLabel = core.getInput("is-fixed-label");
export const githubToken = core.getInput("token");
export const username = core.getInput("username");
export const password = core.getInput("password");
export const severityThreshold = core.getInput("severity-threshold");
export const runQualityChecks = core.getInput("run-quality-checks");
export const maxCreationRetryCount = core.getInput("max-create-retry");

export function isRunQualityChecksEnabled(): boolean {
    return runQualityChecks.toLowerCase() === "true";
}

export function validateRequiredInputs() {
    if (!wontFixLabel)
        throw new Error("'wont-fix-label' input is not supplied. Provide a label to use");
    if (!noFixYetLabel)
        throw new Error("'no-fix-label' input is not supplied. Provide a label to use");
    if (!isFixedLabel)
        throw new Error("'is-fixed-label' input is not supplied. Provide a label to use");
    if (!githubToken)
        throw new Error("'token' input is not supplied. Set it to a PAT/GITHUB_TOKEN");
}