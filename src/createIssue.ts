
import * as core from '@actions/core';
import * as github from '@actions/github';
import {githubToken, isFixedLabel} from "./inputHelper";
import { Octokit } from '@octokit/rest';
import * as inputHelper from './inputHelper'
import { SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_UNKNOWN } from './trivyHelper'

export interface Issue {
    title: string
    labels?: string[]
    body?: string
}


const dockerLabel = "docker :whale:"
const securityLabel = "security :closed_lock_with_key:"

const csastLabel = "CSAT:"
export const SecurityLevels = [SEVERITY_UNKNOWN,SEVERITY_LOW,SEVERITY_MEDIUM,SEVERITY_HIGH,SEVERITY_CRITICAL]

export function getSecurityLevel(level:string):number {
    return SecurityLevels.findIndex(lvl => lvl.toLowerCase() === level.toLowerCase())
}

export const SecurtiyLabels = {
    [SEVERITY_CRITICAL]: [dockerLabel,securityLabel,csastLabel+"1",SEVERITY_CRITICAL.toLowerCase()],
    [SEVERITY_HIGH]: [dockerLabel,securityLabel,csastLabel+"2",SEVERITY_HIGH.toLowerCase()],
    [SEVERITY_MEDIUM]: [dockerLabel,securityLabel,csastLabel+"2",SEVERITY_MEDIUM.toLowerCase()],
    [SEVERITY_LOW]: [dockerLabel,securityLabel,csastLabel+"3",SEVERITY_LOW.toLowerCase()],
    [SEVERITY_UNKNOWN]: [dockerLabel,securityLabel,csastLabel+"3",SEVERITY_UNKNOWN.toLowerCase()],
}

//used to cache issues list
let issues = [];

async function getIssuesList(client: Octokit & any){
    if (issues.length == 0) {
        issues = await client.paginate(client.rest.issues.listForRepo, { ...github.context.repo })
    }
    return issues
}

async function createIssue(client:Octokit & any,issue:Issue):Promise<any>{
    return await client.rest.issues.create({...github.context.repo, ...issue})
}
async function reopenIssue(client:Octokit & any,issue_number:number) {
    await client.rest.issues.update({...github.context.repo, issue_number, state: 'open'})
    await client.rest.issues.createComment({...github.context.repo,issue_number, body: `CVE remains present in image, reopening issue. 
If this issue has already been applied please apply the \`${inputHelper.isFixedLabel}\` and close this issue again.`})
}


async function removeLabelFromIssue(client:Octokit & any,issue_number:number, name: string) {
    await client.rest.issues.removeLabel({...github.context.repo, issue_number,name})
}

async function issueCanBeFixedNow(client:Octokit & any,issue_number:number,fixedVersion:string){
    await removeLabelFromIssue(client,issue_number,inputHelper.noFixYetLabel)
    await client.rest.issues.createComment({...github.context.repo,issue_number, body: `A Fix can be found now by updating to version(s) ${fixedVersion}`})
}

export async function createAnIssue(issue:Issue,fixedVersion?: string):Promise<void>{
    try {
        const client = github.getOctokit(githubToken)
        const issuesList = await getIssuesList(client)
        const issueExists = issuesList.findIndex(({title}) => title === issue.title)
        if ( issueExists !== -1 ) {
                const { id, state, labels:issueLabels } = issuesList[issueExists]
                const hasWontFix = (issueLabels.findIndex(({name}) => name === inputHelper.wontFixLabel) !== -1)
                const isFixed = (issueLabels.findIndex(({name}) => name === inputHelper.isFixedLabel) !== -1)
                const cantFixLabel = (issueLabels.findIndex(({name}) => name === inputHelper.noFixYetLabel) !== -1)
                if (state === "closed" && hasWontFix) {
                    core.debug(`issue has wont fix and is closed. doing nothing.`)
                }else if(state === "closed" && !hasWontFix && isFixed) {
                    core.debug(`issue has been fixed. doing nothing.`)
                }else if(state === "closed" && !hasWontFix && !isFixed) {
                    core.debug(`reopening issue. doing nothing.`)
                    await reopenIssue(client,id)
                }
                else if(state === "open" && cantFixLabel && fixedVersion !== undefined){
                    await issueCanBeFixedNow(client,id,fixedVersion)
                }
        }
        else if (issueExists == -1 ) {
            core.debug(`new issue, creating ${issue.title}`)
            const newIssue = await createIssue(client,issue)
            issues.push(newIssue)//prevent duplication from US
        }
    }catch (e) {
        core.error(e)
    }

}
