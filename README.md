# Container Scan

This action is a clone with modifications to the [Azure Container Scan](https://github.com/Azure/container-scan) Github action 

This action can be used to help you add some additional checks to help you secure your Docker Images in your  CI. This would help you attain some confidence in your docker image before pushing them to your container registry or a deployment.

It internally uses `Trivy` for running certain kinds of scans on these images. 
- [`Trivy`](https://github.com/aquasecurity/trivy) helps you find the common vulnerabilities within your docker images. 


Please checkout [Trivy](https://github.com/aquasecurity/trivy/blob/main/LICENSE) licenses.

## Action inputs
<table>
  <thead>
    <tr>
      <th width="25%">Action input</th>
      <th width="65%">Description</th>
      <th width="10%">Default Value</th>
    </tr>
  </thead>
  <tr>
    <td><code>image-names</code></td>
    <td>(Required) Comma or space seperated list of Docker images to be scanned</td>
    <td>''</td>
  </tr>
  <tr>
    <td><code>severity-threshold</code></td>
    <td>(Optional) Minimum severity threshold set to control flagging of the vulnerabilities found during the scan. The available levels are: (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL); if you set the severity-threshold to be `MEDIUM` every CVE found of a level higher than or equal to `MEDIUM` would be displayed</td>
    <td>HIGH</td>
  </tr>
 <tr>
    <td><code>run-issue-create</code></td>
    <td>(Optional) This is a boolean value. When set to `true` enabled github issue creation</td>
    <td>true</td>
  </tr>
 <tr>
    <td><code>wont-fix-label</code></td>
    <td>(Optional) Label to be used to identify issues that wont be fixed</td>
    <td>wontfix</td>
  </tr>
  <tr>
    <td><code>no-fix-label</code></td>
    <td>(Optional) Label to be used to identify issues that currently cannont be fixed</td>
    <td>no-fix</td>
  </tr> 
  <tr>
    <td><code>is-fixed-label</code></td>
    <td>(Optional) Label to be used to identify issues that have been fixed, This helps to prevent reopening of issues if they are found to be remaining.</td>
    <td>fixed</td>
  </tr>
 <tr>
    <td><code>max-create-retry</code></td>
    <td>(Optional) Maximum number of times to try and create a github issue, After this call it a day</td>
    <td>2</td>
  </tr>
  <tr>
    <td><code>username</code></td>
    <td>(Optional) Username to authenticate to the Docker registry. This is only required when you're trying to pull an image from your private registry</td>
    <td>''</td>
  </tr>
  <tr>
    <td><code>password</code></td>
    <td>(Optional) Password to authenticate to the Docker registry. This is only required when you're trying to pull an image from your private registry</td>
    <td>''</td>
  </tr>
  <tr>
    <td><code>token</code></td>
    <td>(Optional) Github token</td>
    <td><code> ${{github.token}} </code></td>
  </tr>
</table>

## Action Outputs
<table style="table-layout: fixed; width: 100%; border: none; border-collapse: collapse; border-spacing: 0;">
  <thead>
    <tr>
      <th style="width: 15%"> Action Output</th>
      <th style="width: 75%;">Description</th>
    </tr>
  </thead>
<tbody>
  <tr>
    <td><code>sarif-report-path</code></td>
    <td>Location of the combined SARIF2.1.0 Report</td>
  </tr>
  <tr>
    <td><code>audit-report-path</code></td>
    <td>Location of the audit log output. Used to identify date and type of scan done on each container.</td>
  </tr>
</tbody>
</table>

## Ignoring vulnerabilities
In case you would like the action to ignore any vulnerabilities and best practice checks, create an allowedlist file at the path `.github/containerscan/allowedlist.yaml` in your repo. Here's an example allowedlist.yaml file.

```yaml
general:
  vulnerabilities:
    - CVE-2003-1307
    - CVE-2007-0086
    - CVE-2019-3462
    - CVE-2011-3374
```

## Example YAML snippets

The following is an example of not just this action, but how this action could be used along with other  actions to setup a CI. 

Where your CI would:
- Build a docker image 
- Scan the docker image for any security vulnerabilities
- Publish it to your private container registry.

```yaml
on: 
  schedule: 
    - cron: '0 0 * * *'

jobs:
  build-secure-and-push:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@master
    - run: docker build . -t demo:${{ github.sha }}
    - uses: cynalytica/container-scan@v0
      with:
        image-names: demo:${{ github.sha }}
```
