
import * as core from '@actions/core';
import * as github from '@actions/github';
import {githubToken} from "./inputHelper";
import { SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_UNKNOWN } from './trivyHelper'

export interface Issue {
    title: string
    labels?: string[]
    body?: string
}

interface issuesArray {
    data:any
}

const dockerLabel = "docker :whale:"
const securityLabel = "security :closed_lock_with_key:"

const csastLabel = "CSAT:"
export const SecurityLevels = [SEVERITY_UNKNOWN,SEVERITY_LOW,SEVERITY_MEDIUM,SEVERITY_HIGH,SEVERITY_CRITICAL]

export function getSecurityLevel(level:string):number {
    return SecurityLevels.findIndex(lvl => lvl.toLowerCase() === level.toLowerCase())
}

export const SecurtiyLabels = {
    SEVERITY_CRITICAL: [dockerLabel,securityLabel,csastLabel+"1",SEVERITY_CRITICAL.toLowerCase()],
    SEVERITY_HIGH: [dockerLabel,securityLabel,csastLabel+"2",SEVERITY_HIGH.toLowerCase()],
    SEVERITY_MEDIUM: [dockerLabel,securityLabel,csastLabel+"2",SEVERITY_MEDIUM.toLowerCase()],
    SEVERITY_LOW: [dockerLabel,securityLabel,csastLabel+"3",SEVERITY_LOW.toLowerCase()],
    SEVERITY_UNKNOWN: [dockerLabel,securityLabel,csastLabel+"3",SEVERITY_UNKNOWN.toLowerCase()],
}

//used to cache issues list
let issues: issuesArray[] = [];

async function getIssuesList(client):Promise<issuesArray[]>{
    if (issues.length == 0) {
        issues = await client.paginate(client.rest.issues.listForRepo,{...github.context.repo,state:'open'})
    }
    return issues
}

export async function createAnIssue(issue:Issue):Promise<void>{
    try {

        const client = github.getOctokit(githubToken)
        const issues = await getIssuesList(client)
        // @ts-ignore
        const issueExists = issues.data.findIndex(({title}) => title == issue.title)
        if (issueExists == -1 ) {
            core.debug(`creating new issue ${issue.title}`)
            const newIssue = await client.rest.issues.create({...github.context.repo, ...issue})
            newIssue.data.id
        }
    }catch (e) {
        core.error(e)
    }

}
