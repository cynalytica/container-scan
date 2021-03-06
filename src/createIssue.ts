
import * as core from '@actions/core';
import { Octokit } from '@octokit/rest';
import * as github from './client/github';
import * as inputHelper from './inputHelper'
import { SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_UNKNOWN } from './trivyHelper'
import * as trivyHelper from "./trivyHelper";

export const globalClient = github.getOctokit(inputHelper.githubToken,{throttle:{
        onRateLimit: (retryAfter, options) => {
            core.warning(
                `Request quota exhausted for request ${options.method} ${options.url}`
            );
            if(options.request.retyCount <= parseInt(inputHelper.maxCreationRetryCount,10)){
                return true
            }
            core.info(`Retrying after ${retryAfter} seconds!`);
            return true;
        },
        onAbuseLimit: (retryAfter, options) => {
            // does not retry, only logs a warning
            if(options.request.retyCount <= parseInt(inputHelper.maxCreationRetryCount,10)){
                return true
            }
            core.warning(
                `Abuse detected for request ${options.method} ${options.url}. Retrying after ${retryAfter} seconds!`
            );
        },
    }})

export interface Issue {
    title: string
    labels?: string[]
    body?: string
}

function arrayToMDlist(arr:string[]): string {

    let ret = ""
    if(arr === undefined || arr === null){
        return ret
    }
    arr.forEach(s => ret += `* [${s}](${s})\r\n`)
    return ret

}

export async function createIssueFromVuln(vuln:trivyHelper.FilterOutput,imageName:string) {
    const severities = trivyHelper.getSeveritiesToInclude();
    if(severities.includes(vuln.severity)) {
        //figure out labels
        const title = `${imageName} ${vuln.vulnerabilityId}`
        const body = `# ${vuln.vulnerabilityId}

${vuln.title}

${vuln.description}

## Version
${vuln.version}

## Fixed Version
${vuln.fixedVersion || `None`} 

## Severity Source
${vuln.severity}

${vuln.severitySource}

## References

${arrayToMDlist(vuln.references)}
`
        //Add in the no-fix label
        const labels = SecurtiyLabels[vuln.severity]
        if(vuln.fixedVersion === undefined){
            labels.push('no-fix')
        }
        const issue: Issue = {
            title,
            body,
            labels: labels,
        }
        await createAnIssue(globalClient,issues,issue,vuln.fixedVersion)
    }


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


interface IssueItem {
    title:string
    id:number
    number: number
    state:'open'|'closed'
    labels:{
        name:string
    }[]
}

//used to cache issues list
export let issues:IssueItem[] = [];

export async function getIssuesList(client?: Octokit & any){
    if (issues.length == 0) {
        issues = await client.paginate(client.rest.issues.listForRepo, { ...github.context.repo , state: 'all'})
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
    try {
        await client.rest.issues.removeLabel({...github.context.repo, issue_number, name})
    }catch (e){
        core.error(`removeLabelFromIssue:${issue_number},${name}, ${e}`)
    }
}

async function issueCanBeFixedNow(client:Octokit & any,issue_number:number,fixedVersion:string,state: 'open'|'closed'){

    if(state === 'closed'){
        try{
            await client.rest.issues.update({...github.context.repo, issue_number, state: 'open'})
        }catch (e){
             core.error(`reopenIssue: ${e}`)
        }
    }

    await removeLabelFromIssue(client,issue_number,inputHelper.noFixYetLabel)
    try{
        await client.rest.issues.createComment({...github.context.repo,issue_number, body: `A Fix can be found now by updating to version(s) ${fixedVersion}`})
    }catch (e){
        core.error(`createComment:${issue_number}, ${e}`)
    }
}

export async function createAnIssue(client: Octokit & any, issuesList: IssueItem[], issue:Issue,fixedVersion?: string):Promise<void>{
    try {
        const issueExists = issuesList.findIndex(({title}) => title === issue.title)
        if ( issueExists !== -1 ) {
                const { number:id, state, labels:issueLabels } = issuesList[issueExists]
                const hasWontFix = (issueLabels.findIndex(({name}) => name === inputHelper.wontFixLabel) !== -1)
                const isFixed = (issueLabels.findIndex(({name}) => name === inputHelper.isFixedLabel) !== -1)
                const cantFixLabel = (issueLabels.findIndex(({name}) => name === inputHelper.noFixYetLabel) !== -1)
                if(state === "closed" && !hasWontFix && !isFixed && !cantFixLabel) {
                    core.info(`Issue is not fixed, and can be fixed reopening issue.`)
                    await reopenIssue(client,id)
                } else if(cantFixLabel && fixedVersion !== undefined){
                    core.info(`Fix has been found. Updating issue`)
                    await issueCanBeFixedNow(client,id,fixedVersion,state)
                }else {
                    core.info(`${id} => ${state} wontFix:${hasWontFix} isFixed:${isFixed} noFix:${cantFixLabel}`)
                }
        }
        else if (issueExists == -1 ) {
            core.debug(`new issue, creating ${issue.title}`)
            const newIssue = await createIssue(client,issue)
            issues.push({...newIssue,title:issue.title})//prevent duplication from US
        }
    }catch (e) {
        core.error(e)
    }

}
