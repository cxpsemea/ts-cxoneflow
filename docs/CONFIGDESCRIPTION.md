## Configuration 

The tool uses a set of configurations, that can be passed in a yaml file, as well as environment variables or command-line arguments.

The configuration processing is as follows:
1. Configurations are read, by default, from a "application.yaml" file, expected to be in the same folder we are running. However, we can indicate another file, by using the command-line argument **--config-file** and passing a complete path for the configuration file we desire. An example of a configuration file can be found [Here](docs/COMFIGYAML.md).
2. Then environment variables are processed, overriding any existing configurations. Environment variables are evaluated in Linux compatible format, therefore they must be in uppercase and prefixed by "CXTOOL_", in the format "CXTOOL_SECTION_SUBSECTION". Examples: **CXTOOL_CXONE_TENANT** or **CXTOOL_JIRA_URL**.
3. Finally, command-line arguments are processed, again overriding any existing configurations. Command-line arguments are expected in the format "--section.subsection".


## Configuration parameters

Below the list of all configuration options available, in their different sections. The "option" column represents command-line format. 

***Note:*** *The --cx-flow prefix is maintained for retro-compatibility with legacy CXSAST CxFlow tool.*

### General configurations

|Option|Description|
|---|---|
|--verbose|To show execution steps to stdout (True/False)|
|--logs-folder|Supply a folder where logs will be written (default will be in "logs" subfolder)|
|--scanid|The scan id to collect the results from. A file name can be supplied, for commodity, that must match the output from the standar CxONE CLI used to scan, which is a json file with a field named "ID" containing the scanid|
|--app|Application name (required for JIRA)|
|--namespace|Namespace for the repository|
|--repository|Repository name|
|--repo-url|Repository URL|
|--branch|Repository branch name|
|--cx-project|CXONE project name|
|--cx-flow.legacymode|When "true", the default, manages feedback tickets with CxFlow compatibility. Otherwise uses CxOne feed-back apps model|
|--cx-flow.contentstyle|How ticket contents are filled. Options are "legacy" or "cxone". By default, it follows the "legacymode" flag|
|--cx-flow.bug-tracker|Currentry, only JIRA is supported|
|--cx-flow.mitre-url|Url for mitre documentation relative to vulnerabilities|
|--cx-flow.wiki-url|Url for wiki documentation relative to vulnerabilities|
|--cx-flow.break-build|Flag to break pipelines on thresholds/policies violations (default is True)|
|--cx-flow.disable-break-build|Have break build disabled in all cases|
|--cx-flow.branches|To filter specific branches usable to feedback (default is any branch)|
|--cx-flow.enabled-vulnerability-scanners|sast, sca, kics (default is sast,sca)|

### CXONE connectivity configurations

|Option|Description|
|---|---|
|--cxone.url|CxONE portal URI, mandatory (example: https://eu.ast.checkmarx.net)|
|--cxone.acl|CxONE access-control IAM URI (like: https://eu.iam.checkmarx.net)|
|--cxone.tenant|CxONE tanant name, mandatory|
|--cxone.clientid|Login client id, mandatory. Use ast_app to use an API key, or a clientid for OAUTH authentication|
|--cxone.apikey|The API key or a client secret when OAUTH is used, mandatory| 
|--cxone.granttype|"refresh_token" for API keys or "client_credentials" for OAUTH (auto-detected if left empty)|
|--cxone.proxy_url|An URI and port for a proxy, if a proxy is used to connect to CxONE| 
|--cxone.proxy_username|Proxy username if proxy requires authentication (only basic authentication is supported)| 
|--cxone.proxy_password|Proxy password if proxy requires authentication (only basic authentication is supported)| 

### SAST results related

***Note:*** *The --cx-flow prefix is maintained for retro-compatibility with legacy CXSAST CxFlow tool.*

|Option|Description|
|---|---|
|--cx-flow.filter-severity|Only consider results with specific severities. An array or, when using command line, a string in the form "Critical,High,Medium,..."|
|--cx-flow.filter-status|Only consider results marked with specific status. An array or, when using command line, a string in the form "Urgent,Confirmed,Proposed Not Expoitable,Not Exploitable,..."|
|--cx-flow.filter-category|Only consider results from specific vulnerabilities. An array or, when using command line, a string in the form "SQL_Injection,Code_Injection,..."|
|--cx-flow.filter-cwe|Only consider results from specific cwe numbers. An array or, when used in command line, a string in the form "123,456,..."|
|--cx-flow.thresholds|Thresholds to verify for build breaking. An array or, when used in command line, a string in the form "new=1,critical=2,high=3,..."|

### KICS (IaC) results related

|Option|Description|
|---|---|
|--kics.filter-severity|Only consider results with specific severities. An array or, when using command line, a string in the form "Critical,High,Medium,..."|
|--kics.filter-status|Only consider results marked with specific status. An array or, when using command line, a string in the form "Urgent,Confirmed,Proposed Not Expoitable,Not Exploitable,..."|
|--kics.filter-category|Only consider results from specific vulnerabilities. An array or, when using command line, a string in the form "Healthcheck Instruction Missing,Unpinned Actions Full Length Commit SHA,..."|
|--kics.thresholds|Thresholds to verify for build breaking. An array or, when used in command line, a string in the form "new=1,critical=2,high=3,..."|

### SCA results related

|Option|Description|
|---|---|
|--sca.filter-severity|Only consider results with specific severities. An array or, when using command line, a string in the form "Critical,High,Medium,..."|
|--sca.filter-status|Only consider results marked with specific status. An array or, when using command line, a string in the form "Urgent,Confirmed,Proposed Not Expoitable,Not Exploitable,..."|
|--sca.filter-score|Only consider result having a cvss score greater or equal a specific value. A value from 0.0 to 10.0. Exmaple: "4.7"|
|--sca.filter-dependency-type|Only cosider results from packaged of specific dependency types: Direct or Transitive|
|--sca.filter-ignore-dev-test|Do not consider results from packages that are DEV or TEST|
|--sca.filter-exploitable-path|Only consider results having exploitable path detected|
|--sca.filter-policy-violation|Only consider results violating policies|
|--sca.thresholds-score|Break build when results cvss score is greater or equal a specific value. A value from 0.0 to 10.0. Exmaple: "4.7"|
|--sca.thresholds|Thresholds to verify for build breaking. An array or, when used in command line, a string in the form "new=1,critical=2,high=3,..."|

### JIRA tickets related

|Option|Description|
|---|---|
|--jira.url|The uri for your JIRA platform, cloud or server|
|--jira.username|The user name connecting to JIRA, or black if a PAT token is used|
|--jira.token|The user password or PAT token for the user connecting to JIRA|
|--jira.verify_ssl|For use on JIRA server instances using self-signed certificates. The default is "true"|
|--jira.cloud|For use on JIRA cloud instances. Recommended to leave empty, for auto-detection|
|--jira.timeout|Timeout for JIRA calls. Default is 10000 msec|
|--jira.project|JIRA project name|
|--jira.issue-type|JIRA issue type. Default is "Bug"|
|--jira.label-tracker|JIRA field name for labels. Default is "labels"|
|--jira.issue-prefix|To prepend JIRA issues with, for special needs. Default is empty|
|--jira.issue-postfix|To append JIRA issues with, for special needs. Default is empty|
|--jira.description-prefix|To prepend JIRA issue descriptions with, for special needs. Default is empty|
|--jira.description-postfix|To append JIRA issue descriptions with, for special needs. Default is empty|
|--jira.sast-issue-summary-format|Format mask for SAST issues, for special needs. Default is empty|
|--jira.sast-issue-summary-branch-format|Format mask for SAST issues for branches, for special needs. Default is empty|
|--jira.sca-issue-summary-format|Format mask for SCA issues, for special needs. Default is empty|
|--jira.sca-issue-summary-branch-formatFormat mask for SCA issues for branches, for special needs. Default is empty|
|--jira.kics-issue-summary-format|Format mask for KICS issues, for special needs. Default is empty|
|--jira.kics-issue-summary-branch-format|Format mask for KICS issues for branches, for special needs. Default is empty|
|--jira.update-comment|Update comments also when updating tickets. When "false", the default, comments are only written when new tickets are created|
|--jira.priorities.Critical|JIRA priority to bind with Checkamrx critical severity. Default is "Highest"|
|--jira.priorities.High|JIRA priority to bind with Checkamrx high severity. Default is "High"|
|--jira.priorities.Medium|JIRA priority to bind with Checkamrx medium severity. Default is "Medium"|
|--jira.priorities.Medium|JIRA priority to bind with Checkamrx low severity. Default is "Low"|
|--jira.priorities.Informational|JIRA priority to bind with Checkamrx informational severity. Default is "Lowest"|
|--jira.open-transition|JIRA transition to set when opening or re-opening a ticket. Default is "In Progress"|
|--jira.close-transition|JIRA transition to set when closing a ticket. Default is "Done"|
|--jira.open-status|JIRA statuses that indicate that a ticket is opened. Array or, if command line, a string. Default is "To Do,Backlog,Selected for Development,In Progress"|
|--jira.closed-status|JIRA statuses that indicate that a ticket is closed. Array or, if command line, a string. Default is "Done"|
|--jira.fields|Custom fields mappings. Refer to [JIRA Fields](docs/JIRAFIELDS.md) and [CxOne fields for mappings](docs/FIELDSMAPPINGS.md)|

