## Yaml configuration example

```
verbose: 
logs-folder:
scanid: 
app: 
namespace: 
repository:
repo-url: 
branch: 
cx-project: 
cx-flow: 
  bug-tracker: JIRA
  filter-severity: 
    - Critical
    - High 
    - Medium
    # - Low
    # - Information
  filter-category: 
    # - SQL_Injection
    # - Code_Injection
    # - Client_DOM_Stored_XSS    
  filter-cwe: 
  filter-status:
    - Urgent
    - Confirmed
    - Proposed Not Exploitable
    # - Not Exploitable
    # - To Verify
  mitre-url: https://cwe.mitre.org/data/definitions/%s.html
  wiki-url: 
  break-build: 
  disable-break-build: 
  branches: 
  enabled-vulnerability-scanners: 
    - sast
    - sca
    - kics
  thresholds: 
    - new: 1
    - critical: 2
    - high: 10
    # - medium: 50
    # - low: 100    
cxone:
  url: https://eu.ast.checkmarx.net
  acl: https://eu.iam.checkmarx.net
  tenant: 
  clientid: ast_app
  apikey: 
  granttype: refresh_token
  proxy_url: 
  proxy_username: 
  proxy_password: 
checkmarx:
  incremental: 
sca:
  filter-severity:
    - Critical
    - High 
    - Medium
    # - Low
    # - Information
  filter-status:
    - Urgent
    - Confirmed
    - Proposed Not Exploitable
    # - Not Exploitable
    # - To Verify
  filter-score: 8.0
  filter-dependency-type: Direct
  filter-ignore-dev-test: false
  filter-policy-violation: false
  filter-exploitable-path: true
  thresholds: 
    - new: 1
    - critical: 2
    - high: 10
    # - medium: 50
    # - low: 100    
  thresholds-score: 0.0        
kics:
  filter-severity:
    - Critical
    - High 
    - Medium
    # - Low
    # - Information
  filter-status:
    - Urgent
    - Confirmed
    - Proposed Not Exploitable
    # - Not Exploitable
    # - To Verify
  filter-category: 
    # - APT-GET Not Avoiding Additional Packages
    # - Missing User Instruction    
  thresholds: 
    - new: 1
    - critical: 2
    - high: 10
    # - medium: 50
    # - low: 100    
jira: 
  url: 
  username: 
  token: 
  verify_ssl: 
  cloud: 
  timeout: 
  project: 
  issue-type: Bug
  label-tracker: labels
  issue-prefix: 
  issue-postfix:
  description-prefix: 
  description-postfix: 
  update-comment: 
  priorities: 
    Critical: High
    High: High
    Medium: Medium
    Low: Low
    Informational: Lowest
  open-transition: In Progress
  close-transition: Done
  open-status: 
    - To Do
    - Backlog
    - Selected for Development
    - In Progress
  closed-status: 
    - Done
  sast-issue-summary-format: 
  sast-issue-summary-branch-format: 
  sca-issue-summary-format: 
  sca-issue-summary-branch-format: 
  kics-issue-summary-format: 
  kics-issue-summary-branch-format: 
  fields: 
  - type: result
    name: category
    jira-field-name: Jira Name
    jira-field-type: text

```