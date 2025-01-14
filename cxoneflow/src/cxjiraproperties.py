

from cxloghandler import cxlogger
from config import config


class jiraproperties(object) :

    def __init__(self, config: config) :
        # Arrange summary formats according to legacymode
        # -----------------------------------------------
        # - True    tickets descriptions and labels are CxFlow compatible (legacy)
        # - False   tickets descriptions and labels are CxOne Feedback Apps compatible
        legacymode = config.value('cx-flow.legacymode', True)
        
        self.url                            = config.value( 'jira.url' )
        self.cloud                          = config.value( 'jira.cloud', True )
        self.verify_ssl                     = config.value( 'jira.verify_ssl', True )
        self.username                       = config.value( 'jira.username' )
        self.token                          = config.value( 'jira.token' )
        self.proxy_url                      = config.value( 'jira.proxy_url' ) 
        self.proxyuser                      = config.value( 'jira.proxy_username' )
        self.proxyuser                      = config.value( 'jira.proxy_username' )
        self.proxypass                      = config.value( 'jira.proxy_password' )
        self.httptimeout                    = config.value( 'jira.http-timeout' )
        self.project                        = config.value( 'jira.project' )        
        self.projectid                      = None      
        self.issuetype                      = config.value( 'jira.issue-type', 'Bug' )
        self.issuetypeid                    = None
        self.labeltracker                   = config.value( 'jira.label-tracker', 'labels' )
        self.issueprefix                    = config.value( 'jira.issue-prefix' )
        self.issueprefix                    = config.value( 'jira.issue-prefix', '' )
        if not self.issueprefix and legacymode :
            self.issueprefix                = 'CX'
        self.issuepostfix                   = config.value( 'jira.issue-postfix', '' )
        self.descriptionprefix              = config.value( 'jira.description-prefix', '' )
        self.descriptionpostfix             = config.value( 'jira.description-postfix', '' )
        self.labeltracker                   = 'labels'
        self.applabelprefix                 = 'app'
        self.ownerlabelprefix               = 'owner'
        self.repolabelprefix                = 'repo'
        self.branchlabelprefix              = 'branch'
        self.projectlabelprefix             = 'project'
        self.falsepositivelabel             = 'false-positive'
        self.falsepositivestatus            = 'FALSE-POSITIVE'
        self.maxjqlresults                  = 50
        self.updatecomment                  = config.value( 'jira.update-comment', False )
        self.updatecommentvalue             = 'Issue still remains'
        self.priorities                     = { 'CRITICAL': 'Highest', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low', 'INFO': 'Lowest' }
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
                
        # Summary formats (the JIRA ticket keys)
        self.sastissuesummaryformat         = config.value( 'jira.sast-issue-summary-format' )
        self.sastissuesummarybranchformat   = config.value( 'jira.sast-issue-summary-branch-format' )
        self.scaissuesummaryformat          = config.value( 'jira.sca-issue-summary-format' )
        self.scaissuesummarybranchformat    = config.value( 'jira.sca-issue-summary-branch-format' )
        self.kicsissuesummaryformat         = config.value( 'jira.kics-issue-summary-format' )
        self.kicsissuesummarybranchformat   = config.value( 'jira.kics-issue-summary-branch-format' )
        
        if legacymode :
            # SAST
            if not self.sastissuesummaryformat :
                self.sastissuesummaryformat = '[PREFIX] [VULNERABILITY] @ [FILENAME][POSTFIX]'
            if not self.sastissuesummarybranchformat :
                self.sastissuesummarybranchformat = '[PREFIX] [VULNERABILITY] @ [FILENAME] [[BRANCH]][POSTFIX]'
            # SCA
            if not self.scaissuesummaryformat :
                self.scaissuesummaryformat = '[PREFIX] : [VULNERABILITY] in [PACKAGE] and [VERSION] @ [REPOSITORY][POSTFIX]'
            if not self.scaissuesummarybranchformat :
                self.scaissuesummarybranchformat = '[PREFIX] : [VULNERABILITY] in [PACKAGE] and [VERSION] @ [REPOSITORY].[BRANCH][POSTFIX]'
            # KICS
            if not self.kicsissuesummaryformat :
                self.kicsissuesummaryformat = '[PREFIX]-KICS [VULNERABILITY] @ [FILENAME][POSTFIX]'
            if not self.kicsissuesummarybranchformat :
                self.kicsissuesummarybranchformat = '[PREFIX]-KICS [VULNERABILITY] @ [FILENAME] [[BRANCH]][POSTFIX]'
        else :
            # SAST
            if not self.sastissuesummaryformat :
                self.sastissuesummaryformat = '[PREFIX] [VULNERABILITY] @ [FILENAME][POSTFIX]'
            if not self.sastissuesummarybranchformat :
                self.sastissuesummarybranchformat = '[PREFIX] [VULNERABILITY] @ [FILENAME][POSTFIX]'
            # SCA
            if not self.scaissuesummaryformat :
                self.scaissuesummaryformat = '[PREFIX] [VULNERABILITY] @ [PACKAGE][POSTFIX]'
            if not self.scaissuesummarybranchformat :
                self.scaissuesummarybranchformat = '[PREFIX] [VULNERABILITY] @ [PACKAGE][POSTFIX]'
            # KICS
            if not self.kicsissuesummaryformat :
                self.kicsissuesummaryformat = '[PREFIX] [VULNERABILITY] @ [FILENAME][POSTFIX]'
            if not self.kicsissuesummarybranchformat :
                self.kicsissuesummarybranchformat = '[PREFIX] [VULNERABILITY] @ [FILENAME][POSTFIX]'

        # Use labels for JIRA tickets seraching
        self.searchwithlablels              = config.value( 'jira.ticket-search-with-labels', True )
        # Fields defined in project/scan tags
        self.taggedfieldscreateonly         = config.value( 'jira.tagged-fields-create-only', False )

        self.__adjustformatmasks()
        # Fields for project/issue type
        self.issuefields                    = None      # To be filled after connect
        self.issuefieldskey                 = 'key'     # To be checked after connect, JIRA Cloud has 'key', JIRA Server as 'fieldId'
        # Fields defined in project/scan tags
        self.tagfields_labels_createonly        = config.value( 'jira.tagged-fields-create-only.Labels', False )
        # Fields defined in config
        self.__fields                       = config.value( 'jira.fields' )
        self.__processcmdlinefields(config)
        self.fields                         = []        # To be filled with processfields call


    def __processcmdlinefields(self, config: config) :
        # Process fields in the command line in the form:
        # --jira.fields.0.type
        # --jira.fields.0.name
        # --jira.fields.0.jira-field-type
        # --jira.fields.0.jira-field-name
        # --jira.fields.0.jira-default-value
        # --jira.fields.0.skip-update
        # --jira.fields.0.offset
        fpos: int = 0
        fkey: str = 'jira.fields.' + str(fpos) + '.type'
        found = config.haskey(fkey)
        if found and not self.__fields :
            self.__fields = []
        while found :
            ftype       = config.value(fkey)
            fname       = config.value('jira.fields.' + str(fpos) + '.name')
            jiratype    = config.value('jira.fields.' + str(fpos) + '.jira-field-type')
            jiraname    = config.value('jira.fields.' + str(fpos) + '.jira-field-name')
            jiradefault = config.value('jira.fields.' + str(fpos) + '.jira-default-value')
            jiraskip    = config.value('jira.fields.' + str(fpos) + '.skip-update')
            jiraoffset  = config.value('jira.fields.' + str(fpos) + '.offset')
            fdata = {}
            if ftype :
                fdata['type'] = ftype
            if fname :
                fdata['name'] = fname
            if jiratype :
                fdata['jira-field-type'] = jiratype
            if jiraname :
                fdata['jira-field-name'] = jiraname
            if jiradefault :
                fdata['jira-default-value'] = jiradefault
            if jiraskip :
                fdata['skip-update'] = jiraskip
            if jiraoffset :
                fdata['offset'] = jiraoffset 
            list(self.__fields).append(fdata)
            fpos += 1
            fkey: str = 'jira.fields.' + str(fpos) + '.type'
            found = config.haskey(fkey)


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
        # Detect what the JIRA field key is. In JIRA Cloud it comes as 'key' while in JIRA Server it comes as 'fieldId'
        if self.issuefields and len(self.issuefields) > 0 and (not 'key' in self.issuefields[0]) :
            if 'fieldId' in self.issuefields[0] :
                self.issuefieldskey = 'fieldId'
            else :
                self.issuefieldskey = 'name'
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
                # Check jira name and key
                # In JIRA Cloud contains a 'key' field while in JIRA server it comes as 'fieldId'
                jira_field = next( filter( lambda el: el['name'] == jiralabel or el[self.issuefieldskey] == jiralabel, self.issuefields ), None )
                # if not jira_field and jiratype not in ['label','security','priority'] :
                if not jira_field and jiratype not in ['label','security','component'] :
                    raise Exception( 'Jira issue field "' + str(jiralabel) + '" was not found for issue type "' + str(self.issuetype) + '"' )
                # Check jira base type
                if jira_field :
                    jiraname        = jira_field.get(self.issuefieldskey)
                    jiralabel       = jira_field.get('name')
                    jiraoperations  = jira_field.get('operations')
                    jirabasetype    = jira_field['schema'].get('type')
                    jirasystype     = jira_field['schema'].get('system')
                    jiraitemtype    = jira_field['schema'].get('items')
                #     if jira_type != 'any' :
                #         if not ( (jira_type and jira_type.lower() == jiratype.lower()) or (jira_syst and jira_syst.lower() == jiratype.lower()) ) :
                #             raise Exception( 'Jira issue type "' + jiratype + '" is not valid for field "' + jiraname + '"' )
                # Check labels name
                if not jiraname and jiratype == 'label' :
                    jiraname = 'labels'
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


