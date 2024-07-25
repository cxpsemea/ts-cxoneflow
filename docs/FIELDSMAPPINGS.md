## CXONE available fields for mappings

All the fields below can be used. Those that are not relevant for a specific scanner will simply return an empty value.

|Type|Field Name|SAST|SCA|KICS|Description|
|---|---|---|---|---|---|
|cx|cx-scan|X|X|X|Retrieves the entire text from the scan tags (minics CxSAST scan notes)|
|cx|*tag-name*|X|X|X|Retrieves the value from a specific project tag name (mimics CxSAST custom fields)|
|static|*any*|X|X|X|The value defined in *jira-default-value* field mapping parameter|
|result|application|X|X|X|Application name as passed in *app* parameter (--app cmdline argument)|
|result|project|X|X|X|Project name as passed in *cx-project* parameter (--cx-project cmdline argument)|
|result|namespace|X|X|X|Namespace as passed in *namespace* parameter (--namespace cmdline argument)|
|result|repo-name|X|X|X|Repository name as passed in *repository* parameter (--repository cmdline argument)|
|result|repo-url|X|X|X|Repository url as passed in *repo-url* parameter (--repo.url cmdline argument)|
|result|branch|X|X|X|Repository name as passed in *branch* parameter (--branch cmdline argument)|
|result|site|X|X|X|The Checkmarx ONE url|
|result|system-date|X|X|X|Current system date in JIRA (checks *offset* field mapping parameter)|
|result|severity|X|X|X|Result severity (Critical, High, Medium, ...)|
|result|issue-link|X|X|X|Link to the issue in CxONE (if available)|
|result|comment|X|X|X|The last comment entered in the result|
|result|similarity-id|X|X|X|The similarity-id (Hash is SAST, GUID in KICS, CVE in SCA)|
|result|not-exploitable|X|X|X|List of line numbers (issues) marked as not exploitable|
|result|category|X||X|The query name (risk name)|
|result|cwe|X|||The vulnerability CWE id|
|result|cve|X|X||The vulnerability CVE id|
|result|recommendation|X||X|The remediation recomendation (SAST references or KICS expected value)|
|result|filename|X||X|Name of the file containing the result|
|result|loc|X|||Scanned number of lines of code|
|result|language|X|||The scanned language containing the result|
|result|platform|||X|The infrastructure platform|
|result|issue-type|||X|The infrastructure issue type|
|result|package-name||X||The package name|
|result|current-version||X||The package current version|
|result|fixed-version||X||The package version containing the fix (if existing)|
|result|newest-version||X||The package newest known version|
|result|dev-dependency||X||Is the package a dev package (True/False)|
|result|test-dependency||X||Is the package a test package (True/False)|
|result|direct-dependency||X||Is the package a direct dependency (True/False)|
|result|risk-score||X||Is the package risk score (CVSS)|
|result|outdated||X||Is the package outdated (True/False)|
|result|violates-policy||X||Is the package/risk violation a policy (True/False)|
