
cxconfigdefaults = {
    "verbose": None,
    "logs-folder": None,
    "scanid": None,
    "app": None,
    "namespace": None,
    "repository": None,
    "repo-url": None,
    "branch": None,
    "cx-project": None,
    "cx-flow": {
        "bug-tracker": "JIRA",
        "filter-severity": [ "Critical", "High", "Medium" ],
        "filter-category": None,
        "filter-cwe": None,
        "filter-status": None,
        "mitre-url": "https://cwe.mitre.org/data/definitions/%s.html",
        "wiki-url": None,
        "break-build": None,
        "disable-break-build": None,
        "branches": None,
        "enabled-vulnerability-scanners": [ "sca", "sast", "kics" ],
        "thresholds": [
            {"new": None},
            {"critical": None},
            {"high": None},
            {"medium": None},
            {"low": None}
        ]
    },
    "cxone": {
        "url": "https://eu.ast.checkmarx.net",
        "acl": "https://eu.iam.checkmarx.net", 
        "tenant": None,
        "apikey": None,
        "clientid": None,
        "granttype": "client_credentials",
        "proxy_url": None,
        "proxy_username": None,
        "proxy_password": None
    },
    "checkmarx": {
        "incremental": False
    },
    "sca": {
        "filter-severity": [ "Critical", "High", "Medium" ],
        "filter-status": None,
        "filter-score": None,
        "filter-dependency-type": None,
        "filter-ignore-dev-test": False,
        "filter-policy-violation": False,
        "filter-exploitable-path": False,
        "thresholds": [
            {"new": None},
            {"critical": None},
            {"high": None},
            {"medium": None},
            {"low": None}
        ],
        "thresholds-score": None        
    },
    "kics": {
        "filter-severity": [ "Critical", "High", "Medium" ],
        "filter-status": None,
        "filter-category": None,
        "thresholds": [
            {"new": None},
            {"critical": None},
            {"high": None},
            {"medium": None},
            {"low": None}
        ]
    },
    "jira": {
        "url": None,
        "username": None,
        "token":  None,
        "verify_ssl": None,
        "cloud": None,
        "timeout": None,
        "project": None,
        "issue-type": "Bug",
        "label-tracker": "labels",
        "issue-prefix": None,
        "issue-postfix": None,
        "description-prefix": None,
        "description-postfix": None,
        "update-comment": False,
        "priorities": {
            "Critical": "High",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Informational": "Lowest"
        },
        "open-transition": "In Progress",
        "close-transition": "Done",
        "open-status": [ "To Do", "Backlog", "Selected for Development", "In Progress" ],
        "closed-status": [ "Done" ],
        "sast-issue-summary-format": None,
        "sast-issue-summary-branch-format": None,
        "sca-issue-summary-format": None,
        "sca-issue-summary-branch-format": None,
        "kics-issue-summary-format": None,
        "kics-issue-summary-branch-format": None,
        "fields": None     
    }
}