
cxconfigdefaults = {
    "cx-flow": {
        "bug-tracker": "JIRA",
        "filter-severity": [ "Critical", "High", "Medium", "Low" ],
        "filter-status": [ "Urgent", "Confirmed", "Proposed Not Exploitable" ],
        "mitre-url": "https://cwe.mitre.org/data/definitions/%s.html",
        "enabled-vulnerability-scanners": [ "sca", "sast", "kics" ] 
    },
    "cxone": {
        "url": "https://eu.ast.checkmarx.net",
        "acl": "https://eu.iam.checkmarx.net", 
    },
    "checkmarx": {
        "incremental": False
    },
    "sca": {
        "filter-severity": [ "Critical", "High", "Medium" ],
        "filter-status": [ "Urgent", "Confirmed", "Proposed Not Exploitable" ],
        "filter-score": 9.0,
        "filter-exploitable-path": False
    },
    "kics": {
        "filter-severity": [ "Critical", "High", "Medium" ],
        "filter-status": [ "Urgent", "Confirmed", "Proposed Not Exploitable" ]
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
        "priorities": {
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Informational": "Lowest"
        },
        "open-transition": "In Progress",
        "close-transition": "Done",
        "open-status": [ "To Do", "Backlog", "Selected for Development", "In Progress" ],
        "closed-status": [ "Done" ]
    }
}