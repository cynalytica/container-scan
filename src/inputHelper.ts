import * as core from '@actions/core';

export const imageNames = core.getInput("image-names");
export const githubToken = core.getInput("token");
export const username = core.getInput("username");
export const password = core.getInput("password");
export const severityThreshold = core.getInput("severity-threshold");
export const runQualityChecks = core.getInput("run-quality-checks");

export function isRunQualityChecksEnabled(): boolean {
    return runQualityChecks.toLowerCase() === "true";
}

export function validateRequiredInputs() {
    if (!githubToken)
        throw new Error("'token' input is not supplied. Set it to a PAT/GITHUB_TOKEN");
}