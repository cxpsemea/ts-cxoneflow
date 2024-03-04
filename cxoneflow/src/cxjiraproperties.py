

from cxloghandler import cxlogger
from config import config


class jiraproperties(object) :

    def __init__(self, config: config) :
        self.url                            = config.value( 'jira.url' )
        self.username                       = config.value( 'jira.username' )
        self.token                          = config.value( 'jira.token' )
        self.proxy_url                      = config.value( 'jira.proxy_url' ) 
        self.proxyuser                      = config.value( 'jira.proxy_username' )
        self.proxyuser                      = config.value( 'jira.proxy_username' )
        self.proxypass                      = config.value( 'jira.proxy_password' )
        self.httptimeout                    = config.value( 'jira.http-timeout', 20000 )
        self.project                        = config.value( 'jira.project' )        
        self.projectid                      = None      
        self.issuetype                      = config.value( 'jira.issue-type', 'Bug' )
        self.issuetypeid                    = None
        self.labeltracker                   = config.value( 'jira.label-tracker', 'labels' )
        self.issueprefix                    = config.value( 'jira.label-prefix' )
        if not self.issueprefix :
            self.issueprefix                = config.value( 'jira.issue-prefix', 'CX' )
        self.issuepostfix                   = config.value( 'jira.label-postfix' )
        if not self.issuepostfix :
            self.issuepostfix               = config.value( 'jira.label-postfix', '' )
        self.descriptionprefix              = config.value( 'jira.description-prefix', '' )
        self.descriptionpostfix             = config.value( 'jira.description-postfix', '' )
        self.labeltracker                   = 'labels'
        self.applabelprefix                 = 'app'
        self.ownerlabelprefix               = 'owner'
        self.repolabelprefix                = 'repo'
        self.branchlabelprefix              = 'repo'
        self.falsepositivelabel             = 'false-positive'
        self.falsepositivestatus            = 'FALSE-POSITIVE'
        self.maxjqlresults                  = 50
        self.updatecomment                  = config.value( 'jira.update-comment', False )
        self.updatecommentvalue             = 'Issue still remains'
        self.priorities                     = {}
        if config.haskey('jira.priorities.Critical') :
            self.priorities['CRITICAL'] = config.value( 'jira.priorities.Critical' ) 
        if config.haskey('jira.priorities.High') :
            self.priorities['HIGH'] = config.value( 'jira.priorities.High' ) 
        if config.haskey('jira.priorities.Medium') :
            self.priorities['MEDIUM'] = config.value( 'jira.priorities.Medium' ) 
        if config.haskey('jira.priorities.Low') :
            self.priorities['LOW'] = config.value( 'jira.priorities.Low' )
        if config.haskey('jira.priorities.Informational') :
            self.priorities['INFO'] = config.value( 'jira.priorities.Informational' )
        elif config.haskey('jira.priorities.Info') :
            self.priorities['INFO'] = config.value( 'jira.priorities.Info' )
        self.opentransition                 = config.value( 'jira.open-transition' )
        self.closetransition                = config.value( 'jira.close-transition' )
        self.openstatus                     = []
        aux                                 = config.value( 'jira.open-status' )        # Is opened
        if aux :
            for status in aux :
                self.openstatus.append( str(status).lower() )
        self.closedstatus                   = []
        aux                                 = config.value( 'jira.closed-status' )      # Is closed
        if aux :
            for status in aux :
                self.closedstatus.append( str(status).lower() )
        # Summary formats
        self.sastissuesummaryformat         = config.value( 'jira.sast-issue-summary-format', '[PREFIX] [VULNERABILITY] @ [FILENAME][POSTFIX]' )
        self.sastissuesummarybranchformat   = config.value( 'jira.sast-issue-summary-branch-format', '[PREFIX] [VULNERABILITY] @ [FILENAME] [[BRANCH]][POSTFIX]' )
        self.scaissuesummaryformat          = config.value( 'jira.sca-issue-summary-format', '[PREFIX] : [VULNERABILITY] in [PACKAGE] and [VERSION] @ [REPO][POSTFIX]' )
        self.scaissuesummarybranchformat    = config.value( 'jira.sca-issue-summary-branch-format', '[PREFIX] : [VULNERABILITY] in [PACKAGE] and [VERSION] @ [REPO].[BRANCH][POSTFIX]' )
        self.kicsissuesummaryformat         = config.value( 'jira.kics-issue-summary-format', '[PREFIX]-KICS [VULNERABILITY] @ [FILENAME][POSTFIX]' )
        self.kicsissuesummarybranchformat   = config.value( 'jira.kics-issue-summary-branch-format', '[PREFIX]-KICS [VULNERABILITY] @ [FILENAME] [[BRANCH]][POSTFIX]' )
        self.__adjustformatmasks()
        # Fields for project/issue type
        self.issuefields                    = None      # To be filled after connect
        # Fields defined in config
        self.__fields                       = config.value( 'jira.fields' )
        self.fields                         = []        # To be filled with processfields call

        # private String closeTransitionField;
        # private String closeTransitionValue;
        # private String closeFalsePositiveTransitionValue;
            
        # private String parentUrl = "";
        # private String grandParentUrl = "";
        # private boolean child = false;

        # private List<String> statusCategoryOpenName = Arrays.asList("To Do", "In Progress", "Reopened");
        # private List<String> statusCategoryClosedName = Arrays.asList("Done", "Resolve", "Closed");
        # @Getter @Setter
        # private String projectKeyScript;
        # private String labelPrefix;
        # @Getter @Setter
                            # private String scaIssueSummaryBranchFormat = "[PREFIX]: [VULNERABILITY] in [PACKAGE] and [VERSION] @ [REPO].[BRANCH][POSTFIX]";
        # private List<String> suppressCodeSnippets;
        # //dynamically set
        # @Getter @Setter
        # private String Version;
        # @Getter @Setter
        # private String DeployType;
        # @Getter @Setter
        # private TokenType TokenType;


    def __adjustformatmasks(self) :
        self.sastissuesummaryformat         = str(self.sastissuesummaryformat).replace( '[', '{' ).replace( '{{', '[{' )
        self.sastissuesummaryformat         = str(self.sastissuesummaryformat).replace( ']', '}' ).replace( '}}', '}]' )
        self.sastissuesummarybranchformat   = str(self.sastissuesummarybranchformat).replace( '[', '{' ).replace( '{{', '[{' )
        self.sastissuesummarybranchformat   = str(self.sastissuesummarybranchformat).replace( ']', '}' ).replace( '}}', '}]' )
        self.scaissuesummaryformat          = str(self.scaissuesummaryformat).replace( '[', '{' ).replace( '{{', '[{' )
        self.scaissuesummaryformat          = str(self.scaissuesummaryformat).replace( ']', '}' ).replace( '}}', '}]' )
        self.scaissuesummarybranchformat    = str(self.scaissuesummarybranchformat).replace( '[', '{' ).replace( '{{', '[{' )
        self.scaissuesummarybranchformat    = str(self.scaissuesummarybranchformat).replace( ']', '}' ).replace( '}}', '}]' )
        self.kicsissuesummaryformat         = str(self.kicsissuesummaryformat).replace( '[', '{' ).replace( '{{', '[{' )
        self.kicsissuesummaryformat         = str(self.kicsissuesummaryformat).replace( ']', '}' ).replace( '}}', '}]' )
        self.kicsissuesummarybranchformat   = str(self.kicsissuesummarybranchformat).replace( '[', '{' ).replace( '{{', '[{' )
        self.kicsissuesummarybranchformat   = str(self.kicsissuesummarybranchformat).replace( ']', '}' ).replace( '}}', '}]' )


    def processfields(self) :
        self.fields = []
        # Process config fields, if any
        if self.__fields and len(self.__fields) > 0 :
            for field in self.__fields :
                cxtype: str         = field.get('type')
                cxname: str         = field.get('name')
                jiraname: str       = None
                jiratype: str       = field.get('jira-field-type')
                jiralabel: str      = field.get('jira-field-name')
                jiradefault: str    = field.get('jira-default-value')
                jiraskip: str       = field.get('skip-update')
                jiraoffset: int     = int(field.get('offset', 0))
                jirabasetype: str   = None
                jirasystype: str    = None
                jiraitemtype: str   = None
                jiraoperations      = None
                # Check type
                if not (cxtype.lower() in [ 'static', 'cx', 'result', 'sca-result', 'sca-results', 'kics-result', 'kics-results' ]) :
                    raise Exception( 'Unsupported field type "' + cxtype + '" in fields list' )
                # Check name
                if not cxname :
                    raise Exception( 'A field name was not supplied' )
                # if cxtype.lower() in [ 'result', 'sca-result', 'sca-results', 'kics-result', 'kics-results' ] :
                #     if not (cxname.lower() in [ 'application', 'project', 'namespace', 'repo-name', 'repo-url', 'branch', 
                #                 'severity', 'category', 'cwe', 'recommendation', 'loc', 'issue-link', 'filename', 'language', 'similarity-id' ]) :
                #         raise Exception( 'Invalid field name "' + cxname + '" supplied' )
                # Check jira name
                jira_field = next( filter( lambda el: el['name'] == jiralabel or el['key'] == jiralabel, self.issuefields ), None )
                # if not jira_field and jiratype not in ['label','security','priority'] :
                if not jira_field and jiratype not in ['label','security'] :
                    raise Exception( 'Jira issue field "' + str(jiralabel) + '" was not found for issue type "' + str(self.issuetype) + '"' )
                # Check jira base type
                if jira_field :
                    jiraname        = jira_field.get('key')
                    jiralabel       = jira_field.get('name')
                    jiraoperations  = jira_field.get('operations')
                    jirabasetype    = jira_field['schema'].get('type')
                    jirasystype     = jira_field['schema'].get('system')
                    jiraitemtype    = jira_field['schema'].get('items')
                #     if jira_type != 'any' :
                #         if not ( (jira_type and jira_type.lower() == jiratype.lower()) or (jira_syst and jira_syst.lower() == jiratype.lower()) ) :
                #             raise Exception( 'Jira issue type "' + jiratype + '" is not valid for field "' + jiraname + '"' )
                # Add to list
                map = { 'type': cxtype.lower(),
                        'name': cxname.lower(),
                        'jiraname': jiraname,
                        'jiratype': jiratype,
                        'label': jiralabel,
                        'default': jiradefault,
                        'skipupdate': jiraskip, 
                        'offset': jiraoffset,
                        'basetype': jirabasetype,
                        'systype': jirasystype,
                        'itemstype': jiraitemtype,
                        'operations': jiraoperations }
                self.fields.append(map)


