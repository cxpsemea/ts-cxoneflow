

import re
from datetime import datetime
from urllib import parse
from cxloghandler import cxlogger
from config import config
from .basefeedback import basefeedback
from .cxproperties import cxproperties
from .cxjiraapicaller import cxjiraapi
from .cxjiraproperties import jiraproperties 


# Constants

HTML_CRLF: str                          = '\r\n'

JIRA_CX_PRODUCT                         = 'CXONE'
JIRA_CX_LEGACY                          = 'CX'

JIRA_ISSUE_LABEL_SAST: str              = 'scanner:SAST'
JIRA_ISSUE_LABEL_SCA: str               = 'scanner:SCA'
JIRA_ISSUE_LABEL_KICS: str              = 'scanner:KICS'

JIRA_SCA_DEV_LABEL: str                 = 'DEV'
JIRA_SCA_PROD_LABEL: str                = 'PROD'

JIRA_LABEL_FIELD_TYPE: str              = 'labels'
JIRA_PRIORITY_FIELD_TYPE: str           = 'priority'
JIRA_SECURITY_FIELD_TYPE: str           = 'security'
JIRA_VALUE_FIELD_TYPE: str              = 'value'
JIRA_NAME_FIELD_TYPE: str               = 'name'
JIRA_CHILD_FIELD_TYPE: str              = 'child'
JIRA_CHILD_FIELD_DELIMITER: str         = ';'

JIRA_SAST_ISSUE_BODY_WITH_BRANCH: str   = '*SAST {}* issue exists @ *{}* in branch *{}*'
JIRA_SAST_ISSUE_BODY: str               = '*SAST {}* issue exists @ *{}*'
JIRA_KICS_ISSUE_BODY_WITH_BRANCH: str   = '*KICS {}* issue exists @ *{}* in branch *{}*'
JIRA_KICS_ISSUE_BODY: str               = '*KICS {}* issue exists @ *{}*'
JIRA_SCA_ISSUE_BODY_WITH_BRANCH: str    = '*SCA {} Vulnerable Package* issue exists @ *{}* in branch *{}*'
JIRA_SCA_ISSUE_BODY: str                = '*SCA {} Vulnerable Package* issue exists @ *{}*'

JIRA_MAX_DESCRIPTION: int           = 32760



class jirafeedback(basefeedback) :


    def __init__(self, config: config, cxparams: cxproperties, scandata, resultdata ) :
        # Read JIRA parameters from config
        self.jiraparams         = jiraproperties(config = config)
        self.jira               = None
        super().__init__(config, cxparams, scandata, resultdata)


    def __initialize(self) :
        # Connect to jira, either with uname+pass or with PAT
        try :
            self.jira = cxjiraapi( fqdn = self.jiraparams.url, username = self.jiraparams.username, apikey = self.jiraparams.token, 
                            iscloud = self.jiraparams.cloud, verifyssl = self.jiraparams.verify_ssl, timeout = self.jiraparams.httptimeout,
                            proxy_url = self.jiraparams.proxy_url, proxy_username = self.jiraparams.proxyuser, proxy_password = self.jiraparams.proxypass )

            jiraversion, jiratype = self.jira.serverinfo()
            cxlogger.verbose( 'Connected to JIRA ' + jiratype + ', ver ' + jiraversion )
        except Exception as e:
            cxlogger.logerror( 'Unable to connect to JIRA at "' + self.jiraparams.url + '"', e )
            raise Exception( 'Unable to connect to JIRA at "' + self.jiraparams.url + '"' )
        
        # Get jira project using key
        project = self.jira.project( self.jiraparams.project )
        self.jiraparams.projectid = project['id'] 

        # Get jira issue type for the project
        issuetypes = self.jira.projectissuetypes( self.jiraparams.projectid )
        for issue in issuetypes :
            if issue['name'] == self.jiraparams.issuetype :
                self.jiraparams.issuetypeid = issue['id']
        if not self.jiraparams.issuetypeid :
            raise Exception( 'Issue type "' + self.jiraparams.issuetype + '" was not found or is not assigned to the project' )
        # Get fields for project/issue
        self.jiraparams.issuefields   = self.jira.projectissuefields(self.jiraparams.projectid, self.jiraparams.issuetypeid )
        # Process fields mappings
        self.jiraparams.processfields()


    def __retrievejiratickets( self, scanner: str ) :
        # # Get existing tickets for scanner
        # jiratickets = []
        # Construct jql
        jqlex = '( ' + self.jiraparams.labeltracker + ' = ' + JIRA_CX_PRODUCT + ' or ' + self.jiraparams.labeltracker + ' = ' + JIRA_CX_LEGACY + ' )'
        if scanner == 'sast' :
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = ' + JIRA_ISSUE_LABEL_SAST
        elif scanner == 'sca' :
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = ' + JIRA_ISSUE_LABEL_SCA
        elif scanner == 'kics' :
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = ' + JIRA_ISSUE_LABEL_KICS
        # From params, Namespace/Repo/Branch provided
        
        if self.cxparams.namespace and self.cxparams.repository and self.cxparams.branch :
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = "' + self.jiraparams.ownerlabelprefix + ':' + self.cxparams.namespace + '"'
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = "' + self.jiraparams.repolabelprefix + ':' + self.cxparams.repository + '"'
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = "' + self.jiraparams.branchlabelprefix + ':' + self.cxparams.branch + '"'
        # From params, only application and repo provided
        elif self.cxparams.application and self.cxparams.repository  :
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = "' + self.jiraparams.applabelprefix + ':' + self.cxparams.application + '"'
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = "' + self.jiraparams.repolabelprefix + ':' + self.cxparams.repository + '"'
        # From params, only application
        elif self.cxparams.application :
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = "' + self.jiraparams.applabelprefix + ':' + self.cxparams.application + '"'
        # Get it
        return self.jira.projectgetissues( self.jiraparams.projectid, self.jiraparams.issuetypeid, jqlex, self.jiraparams.maxjqlresults )


    def __getscuritylevel( self, jirafieldname: str, value: str ) :
        jira_field = next( filter( lambda el: el['name'] == jirafieldname or el['key'] == jirafieldname, self.jiraparams.issuefields ), None )
        if jira_field :
            allowed_values = jira_field['allowedValues']
            if allowed_values and len(allowed_values) > 0 :
                for allowed_value in allowed_values :
                    if str(allowed_value).uppper() == value.upper() :
                        return allowed_value
        return None


    def __getsummary( self, scanner: str, resultelement ) :
        template        = ''
        prefix          = self.jiraparams.issueprefix
        postfix         = self.jiraparams.issuepostfix
        # repository      = self.cxparams.repository if self.cxparams.repository else ''
        branch          = self.cxparams.branch if self.cxparams.branch else ''

        if scanner == 'sca' :
            vulnerability   = resultelement['id']
            packagename     = resultelement['packagename']
            packageversion  = resultelement['packageversion']
            packagerepo     = resultelement['packagerepository']
            if branch :
                template = self.jiraparams.scaissuesummarybranchformat
                summary  = template.format( PREFIX = prefix, VULNERABILITY = vulnerability, PACKAGE = packagename, VERSION = packageversion, REPO = packagerepo, BRANCH = branch, POSTFIX = postfix )
            else :
                template = self.jiraparams.scaissuesummaryformat
                summary  = template.format( PREFIX = prefix, VULNERABILITY = vulnerability, PACKAGE = packagename, VERSION = packageversion, REPO = packagerepo, POSTFIX = postfix )
        elif scanner == 'kics' :
            vulnerability = resultelement['queryname']
            filename      = resultelement['filename']
            if branch :
                template = self.jiraparams.kicsissuesummarybranchformat
                summary  = template.format( PREFIX = prefix, VULNERABILITY = vulnerability, FILENAME = filename, BRANCH = branch, POSTFIX = postfix )
            else :
                template = self.jiraparams.kicsissuesummaryformat
                summary  = template.format( PREFIX = prefix, VULNERABILITY = vulnerability, FILENAME = filename, POSTFIX = postfix )
        else :
            vulnerability = resultelement['queryname']
            filename      = resultelement['filename']
            if branch :
                template = self.jiraparams.sastissuesummarybranchformat
                summary  = template.format( PREFIX = prefix, VULNERABILITY = vulnerability, FILENAME = filename, BRANCH = branch, POSTFIX = postfix )
            else :
                template = self.jiraparams.sastissuesummaryformat
                summary  = template.format( PREFIX = prefix, VULNERABILITY = vulnerability, FILENAME = filename, POSTFIX = postfix )

        if len(summary) > 255 :
            summary = summary[:254]

        return str(summary)



    def __getdatetimestring( self, value: str ) :

        if not value :
            return ''

        xinput = value.replace('T', ' ')
        xinput = xinput.replace('Z', '')
        xinput = xinput.replace('UTC', '')
        xinput = xinput.replace('/', '-')
        xmask  = '%Y-%m-%d %H:%M:%S.%f%z'

        # Handle timezone displacement
        tzinfo = '+0000'
        tzpos = xinput.find('+', 18)
        if tzpos > 0 :
            tzinfo      = '+' + xinput[tzpos+1:].replace(':', '')
            xinput      = xinput[:tzpos]
        else :
            tzpos = xinput.find('-', 18)
            if tzpos > 0 :
                tzinfo      = '-' + xinput[tzpos+1:].replace(':', '')
                xinput      = xinput[:tzpos]

        # Handle milisecs / microsecs
        microsec = '000000'
        micropos = xinput.find('.')
        if micropos > 0 :
            micros      = int(xinput[micropos+1:])
            xinput      = xinput[:micropos]
            if micros > 0 :
                if micros <= 999 :
                    micros = micros * 1000
                microsec = str(micros)
    
        xinput = xinput + '.' + microsec + tzinfo

        try :
            datet = datetime.strptime( xinput, xmask )
            return datet.isoformat()
        except :
            pass

        return ''



    def __constructfieldsmappings( self, scanner: str, resultelement, labels: list, existingjiraticket = None ) :
        fields = []

        cxprojectname: str  = self.cxparams.cxproject
        if not cxprojectname :
            cxprojectname = self.scandata['projectName']

        cxloc: int  = None
        for status in self.scandata['statusDetails'] :
            if status['name'] == 'sast' :
                aux = status.get('loc')
                if aux: 
                    cxloc = int(aux)

        for field in self.jiraparams.fields :

            jirago: bool        = True

            ftype: str          = field['type'].lower()
            fname: str          = field['name']
            jiraname: str       = field['jiraname']
            jiratype: str       = field['jiratype']
            jiradefault: any    = field['default']
            jiraskip: bool      = field['skipupdate']
            jiraoffset: int     = field['offset'] if field['offset'] else 0
            basetype: str       = field['basetype']
            systype: str        = field['systype']
            itemstype: str      = field['itemstype']
            operations          = field['operations']
            jiralabel           = field['label']

            # Default field value
            fieldvalue          = None

            if existingjiraticket and jiraskip :
                cxlogger.logdebug( 'Skip update to field "' + jiralabel + '"' )
                jirago = False

            if jiraname.lower() == 'labels' :
                cxlogger.logwarning( 'Configuring the Labels parameter would affect issue tracking and might result in duplicate bug creation or bugs not closing or opening.' )

            if not ftype :
                cxlogger.logwarning( 'Field type not supplied for custom field: ' + fname + '. Using "result" by default.' )
                ftype = 'result'

            if not existingjiraticket :
                updateoperation = 'new'
            elif existingjiraticket and not (jiraname.lower() == 'labels') and jirago :
                if 'set' in operations :
                    updateoperation = 'set'
                # elif 'edit' in operations :
                #     updateoperation = 'edit'
                else :
                    updateoperation = None            
                if not updateoperation :
                    cxlogger.logdebug( 'Skip update to field "' + jiralabel + '"' )

            if not updateoperation :
                jirago = False

            if jirago:

                # Custom fields/tags
                if ftype == 'cx' :

                    # Custom fields/tags from scan
                    if fname == 'cx-scan' :
                        fieldvalue = self.scandata['scan-tags-text']
                        if not fieldvalue and jiradefault :
                            fieldvalue = jiradefault
                        else :
                            fieldvalue = None
                    # Custom fields/tags from project
                    else :
                        ftag    = next( filter( lambda el: el['name'].lower() == fname.lower(), self.scandata['project-tags'] ), None )
                        if ftag :
                            fieldvalue = ftag['value']
                        if not fieldvalue and jiradefault :
                            fieldvalue = jiradefault

                # Static value
                elif ftype == 'static' :
                    fieldvalue = jiradefault

                else :

                    # Common fields (all scanners)
                    if fname == 'application' :
                        fieldvalue = self.cxparams.application                          
                    elif fname == 'project' :
                        fieldvalue = cxprojectname
                    elif fname == 'namespace' :
                        fieldvalue = self.cxparams.namespace
                    elif fname == 'repo-name' :
                        fieldvalue = self.cxparams.repository
                    elif fname == 'repo-url' :
                        ftext = self.cxparams.repo_url
                        if ftext and ('gitlab-ci-token' in ftext) and ('@' in ftext) :
                            fieldvalue = ftext[:8] + ftext[ftext.find('@')+1:]
                        else :
                            fieldvalue = ftext
                    elif fname == 'branch' :
                        fieldvalue = self.cxparams.branch
                    elif fname == 'severity' :
                        fieldvalue = resultelement['severity']
                    elif fname == 'system-date' :
                        date = datetime.now()
                        if jiraoffset and jiraoffset != 0 :
                            date = date + datetime.timedelta(days = jiraoffset)
                        fieldvalue = date.strftime('%Y-%m-%d')
                    elif fname == 'site' :
                        fieldvalue = self.cxparams.cxurl
                    elif fname == 'issue-link' :
                        fieldvalue = resultelement['cxonelink']
                    elif fname == 'comment' :
                        fieldvalue = resultelement['comment']
                    elif fname == 'similarity-id' :
                        fieldvalue = resultelement['similarityid']
                    elif fname == 'not-exploitable' :
                        ftext = []
                        for item in resultelement['results'] :
                            if str(item['state']).lower() == 'not_exploitable' :
                                ftext.append(str(item['line']))
                        if len(ftext) > 0 :
                            fieldvalue = ','.join(ftext)

                    # Sast result
                    if scanner == 'sast' :
                        if fname == 'category' :
                            fieldvalue = resultelement['queryname']
                        elif fname == 'cwe' :
                            fieldvalue = resultelement['cwe']
                        elif fname == 'cve' :
                            fieldvalue = None       # Not available for sast
                        elif fname == 'recommendation' :
                            ftext = []
                            if resultelement['cxonelink'] :
                                ftext.append( 'Checkmarx Link: ' + resultelement['cxonelink'] )
                            if self.cxparams.mitre_url and resultelement['cwe'] :
                                txt = self.cxparams.mitre_url % (str(resultelement['cwe']))
                                ftext.append( 'Mitre Details: ' + txt )
                            if self.cxparams.wiki_url :
                                ftext.append( 'Guidance: ' + self.cxparams.wiki_url )
                            if len(ftext) > 0 :
                                fieldvalue = HTML_CRLF.join(ftext)
                        elif fname == 'loc' :
                            fieldvalue = cxloc
                        elif fname == 'filename' :
                            fieldvalue = resultelement['filename']
                        elif fname == 'language' :
                            fieldvalue = resultelement['language']

                    # Kics result
                    if scanner == 'kics' :
                        if fname == 'category' :
                            fieldvalue = resultelement['queryname']
                        elif fname == 'platform' :
                            fieldvalue = resultelement['platform']
                        elif fname == 'filename' :
                            fieldvalue = resultelement['filename']
                        elif fname == 'issue-type' :
                            fieldvalue = resultelement['issueType']
                        elif fname == 'recommendation' :
                            fieldvalue = resultelement['expectedValue']

                    # Sca result
                    if scanner == 'sca' :

                        if fname == 'package-name' :
                            fieldvalue = resultelement['packagename']
                        elif fname == 'current-version' :
                            fieldvalue = resultelement['packageversion']
                        elif fname == 'fixed-version' :
                            fieldvalue = resultelement['recommendedversion']
                        elif fname == 'newest-version' :
                            fieldvalue = resultelement['newestversion']
                        elif fname == 'locations' :
                            ftext = []
                            for item in resultelement['packagedata'] :
                                if item.get('type') and item.get('url') :
                                    ftext.append( item.get('type') + ': ' + item.get('url') )
                            if len(ftext) > 0 :
                                fieldvalue = HTML_CRLF.join(ftext)
                        elif fname == 'dev-dependency' :
                            fieldvalue = str(bool(resultelement['isdev'])).upper()
                        elif fname == 'test-dependency' :
                            fieldvalue = str(bool(resultelement['istest'])).upper()
                        elif fname == 'direct-dependency' :
                            fieldvalue = str(str(resultelement['relation']).upper() == 'DIRECT').upper()
                        elif fname == 'risk-score' :
                            fieldvalue = resultelement['cvss']
                        elif fname == 'outdated' :
                            fieldvalue = str(not resultelement['packageversion'] == resultelement['newestversion'] ).upper()
                        elif fname == 'violates-policy' :
                            fieldvalue = str(resultelement.get('violatedpoliciescount') and resultelement.get('violatedpoliciescount') > 0).upper()
                        elif fname == 'cve' :
                            fieldvalue = resultelement['cve']

                # If the value is missing, check if a default value was specified
                if (not fieldvalue) and jiradefault :
                    fieldvalue = jiradefault

                if fieldvalue :

                    # If jira type is not defined, use default = text
                    if not jiratype :
                        jiratype = 'text'

                    # Datetime value conversions
                    if (basetype == 'date') or (basetype == 'datetime') :
                        fieldvalue = self.__getdatetimestring( str(fieldvalue) )

                    if jiratype == JIRA_SECURITY_FIELD_TYPE :
                        xvalue = self.__getscuritylevel( jiraname, str(fieldvalue) ) 
                        if xvalue :
                            fields.append( { jiraname : xvalue } )
                    elif jiratype == 'text' :
                        fields.append( { jiraname : str(fieldvalue) } )
                    elif jiratype == 'component' :
                        xvalue = []
                        values = str(fieldvalue).split(',')
                        for value in values :
                            if str(value) :
                                xvalue.append( { 'name' : str(value).strip() } )
                        fields.append( { jiraname : xvalue}  )
                    elif jiratype == 'label' :
                        # Do not check for label updates, it will be verifyed later
                        xvalue = []
                        values = str(fieldvalue).split(',')
                        for value in values :
                            if str(value) :
                                xvalue.append( re.sub( '[^a-zA-Z0-9:\\-_]+', '_', str(value) ) )
                        if len(xvalue) > 0 :
                            if jiraname.lower() == self.jiraparams.labeltracker :
                                labels.append( fname + ':' + ''.join(xvalue) )
                            else :
                                fields.append( { jiraname : xvalue }  )
                    elif jiratype == 'single-select' :
                        fields.append( { jiraname : { JIRA_VALUE_FIELD_TYPE : fieldvalue } }  )
                    elif jiratype == 'radio' :
                        fields.append( { jiraname : { JIRA_VALUE_FIELD_TYPE : fieldvalue } }  )
                    elif jiratype == 'multi-select' :
                        xvalue = []
                        values = str(fieldvalue).split(',')
                        for value in values :
                            if str(value) :
                                xvalue.append( { JIRA_VALUE_FIELD_TYPE : value } )
                        if len(xvalue) > 0 :
                            fields.append( { jiraname : xvalue }  )
                    elif jiratype == 'cascading-select' :
                        # expected value format is "parent;child"
                        # neither can be empty; enclose in quotes if spaces/special characters
                        # must match case
                        xvalue = ''
                        values = str(fieldvalue).split('JIRA_CHILD_FIELD_DELIMITER')
                        if len(values) == 2 :
                            xvalue = { JIRA_VALUE_FIELD_TYPE : str(values[0]).strip(), JIRA_CHILD_FIELD_TYPE : { JIRA_VALUE_FIELD_TYPE : str(values[1]).strip() } }
                            fields.append( { jiraname : xvalue }  )
                        else :
                            cxlogger.logwarning( 'Invalid value for jira field type "' + jiratype + '"' )
                    elif jiratype == 'single-version-picker' :
                        fields.append( { jiraname : { JIRA_NAME_FIELD_TYPE : str(fieldvalue) } }  )
                    elif jiratype == 'multi-version-picker' :
                        xvalue = []
                        values = str(fieldvalue).split(',')
                        for value in values :
                            if str(value) :
                                xvalue.append( { JIRA_NAME_FIELD_TYPE : str(value) } )
                        if len(xvalue) > 0 :
                            fields.append( { jiraname : xvalue }  )
                    else :
                        cxlogger.logwarning( 'Field type "' + jiratype + '" is not a valid option' )

        return fields
    

    def __contructbody( self, scanner: str, resultelement ) :

        body    = []

        branch  = self.cxparams.branch if self.cxparams.branch else ''

        resultsurl = self.cxparams.cxurl + '/results/' + self.scandata['projectId'] + '/' + self.scandata['id']

        if self.jiraparams.descriptionprefix :
            body.append( self.jiraparams.descriptionprefix )

        if scanner == 'sca' :
            if branch :
                body.append( JIRA_SCA_ISSUE_BODY_WITH_BRANCH.format( str(resultelement['severity']).upper(), str(resultelement['packagename']), branch ) + HTML_CRLF + HTML_CRLF )
            else :
                body.append( JIRA_SCA_ISSUE_BODY.format( str(resultelement['severity']).upper(), str(resultelement['packagename']) ) + HTML_CRLF + HTML_CRLF )
            if resultelement['description'] :
                body.append( str(resultelement['description']).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF + HTML_CRLF )
        elif scanner == 'kics' :
            if branch :
                body.append( JIRA_KICS_ISSUE_BODY_WITH_BRANCH.format( str(resultelement['queryname']), str(resultelement['filename']), branch ) + HTML_CRLF + HTML_CRLF )
            else :
                body.append( JIRA_KICS_ISSUE_BODY.format( str(resultelement['queryname']), str(resultelement['filename']) ) + HTML_CRLF + HTML_CRLF )
            if resultelement['description'] :
                body.append( str(resultelement['description']).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF + HTML_CRLF )
        else :
            if branch :
                body.append( JIRA_SAST_ISSUE_BODY_WITH_BRANCH.format( str(resultelement['queryname']), str(resultelement['filename']), branch ) + HTML_CRLF + HTML_CRLF )
            else :
                body.append( JIRA_SAST_ISSUE_BODY.format( str(resultelement['queryname']), str(resultelement['filename']) ) + HTML_CRLF + HTML_CRLF )
            if resultelement['description'] :
                body.append( str(resultelement['description']).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF + HTML_CRLF )

        ftext = self.cxparams.repo_url
        if ftext and ('gitlab-ci-token' in ftext) and ('@' in ftext) :
            repourl = ftext[:8] + ftext[ftext.find('@')+1:]
        else :
            repourl = ftext

        cxprojectname: str  = self.cxparams.cxproject
        if not cxprojectname :
            cxprojectname = self.scandata['projectName']

        if self.cxparams.namespace :
            body.append( '*Namespace:* ' + str(self.cxparams.namespace).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
        if self.cxparams.repository :
            body.append( '*Repository:* ' + str(self.cxparams.repository).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
        if self.cxparams.branch :
            body.append( '*Branch:* ' + str(self.cxparams.branch).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
        if repourl :
            body.append( '*Repository Url:* ' + repourl + HTML_CRLF )
        if self.cxparams.application :
            body.append( '*Application:* ' + str(self.cxparams.application).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
        if cxprojectname :
            body.append( '*Cx-Project:* ' + cxprojectname.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
        if resultelement['severity'] :
            body.append( '*Severity:* ' + str(resultelement['severity']) + HTML_CRLF )
        if resultelement['cwe'] :
            body.append( '*CWE:* ' + str(resultelement['cwe']) + HTML_CRLF )
        if resultelement['status'] :
            body.append( '*Status:* ' + str(resultelement['status']) + HTML_CRLF )
        if resultelement['state'] :
            body.append( '*State:* ' + str(resultelement['state']) + HTML_CRLF )

        body.append( HTML_CRLF )
        body.append( '*Additional Info*' + HTML_CRLF )
        body.append( '----' + HTML_CRLF )

        if scanner == 'sast' :
            if self.cxparams.mitre_url and resultelement['cwe'] :
                body.append( '[Mitre Details|' + self.cxparams.mitre_url % (str(resultelement['cwe'])) + ']' + HTML_CRLF)
            if self.cxparams.wiki_url :
                body.append( '[Guidance|' + self.cxparams.wiki_url + ']' + HTML_CRLF)
            if resultelement['cwe'] and resultelement['queryid'] :
                body.append( '[Recommended Fix|' + resultsurl + '/sast/description/' + str(resultelement['cwe']) + '/' + str(resultelement['queryid']) + ']' + HTML_CRLF)
            items_on  = []
            items_off = []                
            for item in resultelement['results'] :
                if str(item['state']).lower() == 'not_exploitable' :
                    items_off.append( item['line'] )
                else :
                    items_on.append( item['line'] )
            items_on.sort()
            items_off.sort()
            if len(items_on) > 0 :
                aux = []
                for item in items_on :
                    aux.append(str(item))
                body.append( 'Lines: ' + ', '.join(aux) + HTML_CRLF)
            if len(items_off) > 0 :
                aux = []
                for item in items_off :
                    aux.append(str(item))
                body.append( 'Lines Marked Not Exploitable: ' + ', '.join(aux) + HTML_CRLF)

        elif scanner == 'kics' :
            if resultelement['platform'] :
                body.append( 'Platform: ' + str(resultelement['platform']).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if resultelement['issuetype'] :
                body.append( 'Issue Type: ' + str(resultelement['issuetype']) + HTML_CRLF)
            if resultelement['value'] :
                body.append( 'Current Value: ' + str(resultelement['value']).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if resultelement['expectedvalue'] :
                body.append( 'Expected Value: ' + str(resultelement['expectedvalue']).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            items_on  = []
            items_off = []                
            for item in resultelement['results'] :
                if str(item['state']).lower() == 'not_exploitable' :
                    items_off.append( item['line'] )
                else :
                    items_on.append( item['line'] )
            items_on.sort()
            items_off.sort()
            if len(items_on) > 0 :
                aux = []
                for item in items_on :
                    aux.append(str(item))
                body.append( 'Lines: ' + ', '.join(aux) + HTML_CRLF)
            if len(items_off) > 0 :
                aux = []
                for item in items_off :
                    aux.append(str(item))
                body.append( 'Lines Marked Not Exploitable: ' + ', '.join(aux) + HTML_CRLF)

        elif scanner == 'sca' :
            if resultelement['id'] :
                body.append( 'Vulnerability ID: ' + str(resultelement['id']) + HTML_CRLF)
            if resultelement['packagename'] :
                body.append( 'Package Name: ' + str(resultelement['packagename']) + HTML_CRLF)
            if resultelement['packagerepository'] :
                body.append( 'Package Repo: ' + str(resultelement['packagerepository']) + HTML_CRLF)
            if resultelement['cvss'] :
                body.append( 'CVSS Score: ' + str(resultelement['cvss']) + HTML_CRLF)
            if resultelement['cve'] :
                body.append( 'CVE: ' + str(resultelement['cve']) + HTML_CRLF)
            if resultelement['releasedate'] :
                body.append( 'Publish Date: ' + str(resultelement['releasedate']) + HTML_CRLF)
            if resultelement['packageversion'] :
                body.append( 'Current Package Version: ' + str(resultelement['packageversion']) + HTML_CRLF)
            if resultelement['recommendedversion'] :
                body.append( 'Remediation Upgrade Recommendation: ' + str(resultelement['recommendedversion']).replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if resultelement['newestversion'] :
                body.append( 'Latest Package Version: ' + str(resultelement['newestversion']) + HTML_CRLF)
            if resultelement['packagerepository'] and resultelement['packagename'] and resultelement['packageversion'] :
                url = self.cxparams.cxurl + '/sca/#/appsec-knowledge-center/package' + \
                    parse.quote(resultelement['packagerepository'], safe = '') + '/' + \
                    parse.quote(resultelement['packagename'], safe = '') + '/' + \
                    parse.quote(resultelement['packageversion'], safe = '')
                body.append( '[Guidance|' + url + ']' + HTML_CRLF)
            if str(resultelement['id']).upper().startswith('CVE-') :
                url = 'https://nvd.nist.gov/vuln/detail/' + str(resultelement['id']).upper().strip()
                body.append( '[Reference – NVD link|' + url + ']' + HTML_CRLF)

        if resultelement['cxonelink'] :
            body.append( '[Checkmarx|' + str(resultelement['cxonelink']) + ']' + HTML_CRLF)


        body.append( HTML_CRLF )

        if self.jiraparams.descriptionpostfix :
            body.append( self.jiraparams.descriptionpostfix )

        data = ''.join(body)
        
        return data[:JIRA_MAX_DESCRIPTION]
    


    def __processjiraticket( self, scanner: str, resultelement, existingjiraticket = None ) :


        # Construct summary
        summary = self.__getsummary( scanner, resultelement )

        # Construct description
        description = self.__contructbody( scanner, resultelement )

        # Construct priority
        priority = None
        if len(self.jiraparams.priorities) > 0 :
            severity = str(resultelement['severity']).upper()
            if severity == 'INFORMATIONAL' :
                priority = self.jiraparams.priorities.get('INFO')
            else :
                priority = self.jiraparams.priorities.get(severity)

        # Set assignee

        # Construct control labels
        labels = []
        labels.append( JIRA_CX_PRODUCT )
        if self.cxparams.namespace and self.cxparams.repository and self.cxparams.branch :
            labels.append( self.jiraparams.ownerlabelprefix + ':' + self.cxparams.namespace )
            labels.append( self.jiraparams.repolabelprefix + ':' + self.cxparams.repository )
            labels.append( self.jiraparams.branchlabelprefix + ':' + self.cxparams.branch )
        # From params, only application and repo provided
        elif self.cxparams.application and self.cxparams.repository  :
            labels.append( self.jiraparams.applabelprefix + ':' + self.cxparams.application )
            labels.append( self.jiraparams.repolabelprefix + ':' + self.cxparams.repository )
        # From params, only application
        elif self.cxparams.application :
            labels.append( self.jiraparams.applabelprefix + ':' + self.cxparams.application )
        # Scanner type
        if scanner == 'sast' :
            labels.append( JIRA_ISSUE_LABEL_SAST )
        elif scanner == 'sca' :
            labels.append( JIRA_ISSUE_LABEL_SCA )
            if resultelement['isdev'] or resultelement['istest'] :
                labels.append( JIRA_SCA_DEV_LABEL )
            else :
                labels.append( JIRA_SCA_PROD_LABEL )
        elif scanner == 'kics' :
            labels.append( JIRA_ISSUE_LABEL_KICS )

        # Contruct field mappings
        fields = self.__constructfieldsmappings( scanner, resultelement, labels, existingjiraticket )

        # Make sure labels are unique
        labels = list(set(labels))

        # Does the issue exist ?
        if not existingjiraticket :
            ticket = self.jira.projectcreateissue( self.jiraparams.projectid, self.jiraparams.issuetypeid, summary, description, fields, labels, priority )
            # Add to CREATED
            cxlogger.verbose( '- JIRA issue ' + ticket['key'] + ' created, type ' + scanner.upper() + ', with key "' + summary + '"' )

        else :
            ticket = existingjiraticket
            ticketkey = ticket.get('key')
            current_status = ticket['fields']['status']['name']
            reopened = False
            # If it's not opened, let's reopen it
            if (str(current_status).lower() in self.jiraparams.closedstatus) :
                if self.jiraparams.opentransition :
                    self.jira.tickettransition( ticketkey, self.jiraparams.opentransition )
                    reopened = True
                else :
                    cxlogger.logwarning( 'Open transtion missing. Cannot reopen "' + str(ticketkey) + '"' )
            # Check if description changed
            newdescription = None
            if description and (not description == ticket['fields'].get('description')) :
                newdescription = description
            # Check if priority changed
            newpriority = None
            ticketpriority = None
            if ticket['fields'].get('priority') :
                ticketpriority = ticket['fields']['priority'].get('name')
            if priority and (not priority == ticketpriority) :
                newpriority = priority
            # Check if labels changed
            newlabels   = []
            existinglabels = ticket['fields'].get('labels')
            if not existinglabels :
                existinglabels = []
            for label in labels :
                found = next( filter( lambda el: el == label, existinglabels), None )
                if not found :
                    newlabels.append(label)
            if len(newlabels) == 0 :
                newlabels = None
            # Check fields
            if len(fields) == 0 :
                fields = None

            if newdescription or newpriority or newlabels or fields :
                self.jira.projecteditissue( ticketkey, newdescription, fields, newlabels, newpriority )

            if reopened :
                cxlogger.verbose( '- JIRA issue ' + ticket['key'] + ' re-opened, type ' + scanner.upper() + ', with key "' + summary + '"' )
            else :
                cxlogger.verbose( '- JIRA issue ' + ticket['key'] + ' still exists, type ' + scanner.upper() + ', with key "' + summary + '"' )

        return ticket




    def __processscannerresults( self, scanner: str ) :

        # Get existing jira tickets for scanner
        cxlogger.verbose( 'Check existing ' + scanner + ' tickets' )
        jiratickets = self.__retrievejiratickets( scanner ) 
        if len(jiratickets) == 0 :
            cxlogger.verbose( '- No existing ' + scanner + ' tickets found' )
        else :
            cxlogger.verbose( '- Found ' + str(len(jiratickets)) + ' ' + scanner + ' tickets' )

        # Check the results
        for ticket in self.resultdata[scanner] :
            ticketsummary = self.__getsummary( scanner, ticket )
            ticket[self.cxparams.ticketkeyname] = ticketsummary
            # Does the ticket exist ?
            jiraticket = next( filter( lambda el: el['fields']['summary'] == ticketsummary, jiratickets ), None )
            # Will create, update, and transition (open/close/reopen)
            self.__processjiraticket( scanner, ticket, jiraticket )

        # Check closed
        for ticket in jiratickets :
            ticketsummary   = ticket['fields'].get('summary')
            ticketkey       = ticket.get('key')
            current_status  = ticket['fields']['status']['name']
            # Does the result still exist ?
            cxresult = next( filter( lambda el: el[self.cxparams.ticketkeyname] == ticketsummary, self.resultdata[scanner] ), None )
            # Shall close it ?
            if not cxresult and (str(current_status).lower() in self.jiraparams.openstatus) :
                if self.jiraparams.closetransition :
                    self.jira.tickettransition( ticketkey, self.jiraparams.closetransition )
                    cxlogger.verbose( '- JIRA issue ' + ticket['key'] + ' closed, type ' + scanner.upper() + ', with key "' + ticketsummary + '"' )    
                else :
                    cxlogger.logwarning( 'Close transtion missing. Cannot close "' + str(ticketkey) + '"' )


        # Clean in up
        jiratickets = None
        return



    # Override
    def processfeedback(self) : 

        # Establish connection to Jira and pre-process Jira parameters
        self.__initialize()

        # Go one scanner at the time
        if self.resultdata['sast'] :
            self.__processscannerresults( 'sast' )
        if self.resultdata['sca'] :
            self.__processscannerresults( 'sca' )
        if self.resultdata['kics'] :
            self.__processscannerresults( 'kics' )

        return