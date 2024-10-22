
import re
import json
from datetime import datetime
from urllib import parse
from requests import HTTPError
from cxloghandler import cxlogger
from config import config
from .basefeedback import basefeedback
from .cxproperties import cxproperties
from .cxjiraapicaller import cxjiraapi
from .cxjiraproperties import jiraproperties 
from .dto.cxcounters import *
from .dto.cxscan import *
from .dto.cxresults import *

# Constants

HTML_CRLF: str                          = '\r\n'

JIRA_SCA_DEV_LABEL: str                 = 'DEV'
JIRA_SCA_TEST_LABEL: str                = 'TEST'
JIRA_SCA_PROD_LABEL: str                = 'PROD'

JIRA_SECURITY_FIELD_TYPE: str           = 'security'
JIRA_VALUE_FIELD_TYPE: str              = 'value'
JIRA_NAME_FIELD_TYPE: str               = 'name'
JIRA_CHILD_FIELD_TYPE: str              = 'child'
JIRA_CHILD_FIELD_DELIMITER: str         = ';'

JIRA_SAST_ISSUE_BODY_WITH_BRANCH: str   = '*SAST {}* issue exists @ *{}* in branch *{}*'
JIRA_SAST_ISSUE_BODY: str               = '*SAST {}* issue exists @ *{}*'
JIRA_SCA_ISSUE_BODY_WITH_BRANCH: str    = '*SCA {} Vulnerable Package* issue exists @ *{}* in branch *{}*'
JIRA_SCA_ISSUE_BODY: str                = '*SCA {} Vulnerable Package* issue exists @ *{}*'
JIRA_KICS_ISSUE_BODY_WITH_BRANCH: str   = '*KICS {}* issue exists @ *{}* in branch *{}*'
JIRA_KICS_ISSUE_BODY: str               = '*KICS {}* issue exists @ *{}*'

JIRA_MAX_DESCRIPTION: int               = 32760



class jirafeedback(basefeedback) :


    def __init__(self, config: config, cxparams: cxproperties, scaninfo: cxscan, results: cxresults ) :
        # Read JIRA parameters from config
        self.jiraparams         = jiraproperties(config = config)
        self.jira               = None
        super().__init__(config, cxparams, scaninfo, results)


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
        
        
    def __intreferences(self) :
        
        # CxFlow compatible
        if self.cxparams.legacymode :
            # Labels
            self.JIRA_CX_PRODUCT                         = 'CXONE'
            self.JIRA_CX_LEGACY                          = 'CX'
            self.JIRA_ISSUE_LABEL_SAST: str              = 'scanner:SAST'
            self.JIRA_ISSUE_LABEL_SCA: str               = 'scanner:SCA'
            self.JIRA_ISSUE_LABEL_KICS: str              = 'scanner:KICS'
            
        # CxOne feedback apps mode
        else :
            # Labels
            self.JIRA_CX_PRODUCT                         = 'Checkmarx'
            self.JIRA_CX_LEGACY                          = 'CX'
            self.JIRA_ISSUE_LABEL_SAST: str              = 'SAST'
            self.JIRA_ISSUE_LABEL_SCA: str               = 'SCA'
            self.JIRA_ISSUE_LABEL_KICS: str              = 'IaC-Security'
            
            
            
    def __processtagfields(self, projecttags: bool ) :
        
        tags = []
        if projecttags :
            source = 'project'
            tags   = self.scaninfo.projecttags
        else :
            source = 'scan'
            tags   = self.scaninfo.tags

        for tag in tags :
            tagkey      = str(tag['name'])
            tagvalue    = str(tag['value'])
            if tagkey and tagvalue and tagkey != tagvalue and tagkey.startswith('feedback-') and tagkey != 'feedback-' :
                jira_name = str(tagkey.split('-', 1)[1])
                # Have we this field name in jira ticket fields (JIRA Cloud contains a 'key' field while in JIRA server it comes as 'fieldId')
                jira_field = next( filter( lambda el: str(el['name']).upper() == jira_name.upper() or str(el[self.jiraparams.issuefieldskey]).upper() == jira_name.upper(), self.jiraparams.issuefields ), None )
                if not jira_field :
                    cxlogger.logwarning( 'Could not find a JIRA field "' + jira_field + '" for ' + source + ' tag "' + tagkey + '", Ignoring' )
                else :
                    jiraname        = jira_field.get(self.jiraparams.issuefieldskey)
                    jiralabel       = jira_field.get('name')
                    jiraoperations  = jira_field.get('operations')
                    jirabasetype    = jira_field['schema'].get('type')
                    jirasystype     = jira_field['schema'].get('system')
                    jiraitemtype    = jira_field['schema'].get('items')
                    # Is this field already populated ?
                    jira_exists = next( filter( lambda el: el['jiraname'] == jira_name, self.jiraparams.fields ), None )
                    # Add it to the list
                    if not jira_exists :
                        jira_type: str = jirabasetype
                        if jira_type.lower() == self.jiraparams.labeltracker :
                            jira_type = 'label'
                        elif jira_type.lower() == 'string' :
                            jira_type = 'text'
                        
                        # Add to list
                        map = { 'type': 'static',
                                'name': jiraname,
                                'jiraname': jiraname,
                                'jiratype': jira_type,
                                'label': jiralabel,
                                'default': tagvalue,
                                'skipupdate': False, 
                                'offset': 0,
                                'basetype': jirabasetype,
                                'systype': jirasystype,
                                'itemstype': jiraitemtype,
                                'operations': jiraoperations }
                    self.jiraparams.fields.append(map)

        

    def __getscuritylevel( self, jirafieldname: str, value: str ) :
        jira_field = next( filter( lambda el: el['name'] == jirafieldname or el[self.jiraparams.issuefieldskey] == jirafieldname, self.jiraparams.issuefields ), None )
        if jira_field :
            allowed_values = jira_field['allowedValues']
            if allowed_values and len(allowed_values) > 0 :
                for allowed_value in allowed_values :
                    if str(allowed_value).uppper() == value.upper() :
                        return allowed_value
        return None



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



    # Get existing JIRA tickets for scanner
    def __retrievejiratickets( self, scanner: str ) :
        # Construct jql
        jqlex = '( ' + self.jiraparams.labeltracker + ' = ' + self.JIRA_CX_PRODUCT + ' or ' + self.jiraparams.labeltracker + ' = ' + self.JIRA_CX_LEGACY + ' )'
        if scanner == 'sast' :
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = ' + self.JIRA_ISSUE_LABEL_SAST
        elif scanner == 'sca' :
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = ' + self.JIRA_ISSUE_LABEL_SCA
        elif scanner == 'kics' :
            jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = ' + self.JIRA_ISSUE_LABEL_KICS
        # CxFlow compatible
        if self.cxparams.legacymode :
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
        else :
            if self.scaninfo.branch :
                jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = "' + self.jiraparams.branchlabelprefix + ':' + self.scaninfo.branch + '"'
            if self.scaninfo.projectname :
                jqlex = jqlex + ' and ' + self.jiraparams.labeltracker + ' = "' + self.jiraparams.projectlabelprefix + ':' + self.scaninfo.projectname + '"'
    
        # Get it all. It uses paged gets of self.jiraparams.maxjqlresults per pages
        try :
            issues = self.jira.projectgetissues( self.jiraparams.projectid, self.jiraparams.issuetypeid, jqlex, self.jiraparams.maxjqlresults )
        except HTTPError as e:
            raise Exception( self.__processjiraexception( False, True, e ) )
        except Exception as e:
            if str(e) :
                raise e
            else :
                raise Exception( 'Error retrieving jira tickets' )
            
        return issues



    def __getsummary( self, scanner: str, ticket: cxresult ) :
        template        = ''
        prefix          = self.jiraparams.issueprefix
        postfix         = self.jiraparams.issuepostfix
        repository      = self.cxparams.repository if self.cxparams.repository else ''
        branch          = self.cxparams.branch if self.cxparams.branch else ''
        
        if scanner == 'sast' :
            cxsastticket: cxsastresult = ticket
            vulnerability = cxsastticket.queryname
            filename      = cxsastticket.filename
            if self.cxparams.legacymode and filename.startswith( '/' ) :
                filename = filename[1:]
            if branch :
                template = self.jiraparams.sastissuesummarybranchformat
            else :
                template = self.jiraparams.sastissuesummaryformat
            summary  = template.format( PREFIX = prefix, VULNERABILITY = vulnerability, FILENAME = filename, REPOSITORY = repository, BRANCH = branch, POSTFIX = postfix )
        elif scanner == 'sca' :
            cxscaticket: cxscaresult = ticket
            vulnerability   = cxscaticket.id
            packagename     = cxscaticket.packageid
            packageversion  = None
            if self.cxparams.legacymode :
                aux = packagename.split('-')
                if len(aux) > 1 :
                    packageversion = aux.pop(len(aux) - 1)
                    packagename = '-'.join(aux)
            if branch :
                template = self.jiraparams.scaissuesummarybranchformat
            else :
                template = self.jiraparams.scaissuesummaryformat
            summary  = template.format( PREFIX = prefix, VULNERABILITY = vulnerability, PACKAGE = packagename, VERSION = packageversion, REPOSITORY = repository, BRANCH = branch, POSTFIX = postfix )
        elif scanner == 'kics' :
            cxkicsticket: cxkicsresult = ticket
            vulnerability = cxkicsticket.queryname
            filename      = cxkicsticket.filename
            if self.cxparams.legacymode and filename.startswith( '/' ) :
                filename = filename[1:]
            if branch :
                template = self.jiraparams.kicsissuesummarybranchformat
            else :
                template = self.jiraparams.kicsissuesummaryformat
            summary  = template.format( PREFIX = prefix, VULNERABILITY = vulnerability, FILENAME = filename, REPOSITORY = repository, BRANCH = branch, POSTFIX = postfix )
        if self.cxparams.legacymode and summary.endswith('@ ') :
            summary = summary.lstrip()
        else :
            summary = summary.strip()
        if len(summary) > 255 :
            summary = summary[:254]
        return str(summary)
    
    
    
    # Body constructed CxFlow legacy model
    def __constructbody_legacy( self, scanner: str, ticket: cxresult ) :

        body    = []

        branch  = self.cxparams.branch if self.cxparams.branch else ''

        if self.jiraparams.descriptionprefix :
            body.append( self.jiraparams.descriptionprefix + HTML_CRLF )
            
        # First line and description
        if scanner == 'sast' :
            cxsastticket: cxsastresult = ticket
            if branch :
                body.append( JIRA_SAST_ISSUE_BODY_WITH_BRANCH.format( cxsastticket.queryname, cxsastticket.filename, branch ) + HTML_CRLF + HTML_CRLF )
            else :
                body.append( JIRA_SAST_ISSUE_BODY.format( cxsastticket.queryname, cxsastticket.filename ) + HTML_CRLF + HTML_CRLF )
            if cxsastticket.description :
                body.append( cxsastticket.description.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF + HTML_CRLF )
        elif scanner == 'sca' :
            cxscaticket: cxscaresult = ticket
            if branch :
                body.append( JIRA_SCA_ISSUE_BODY_WITH_BRANCH.format( cxscaticket.severity.upper(), cxscaticket.packagename, branch ) + HTML_CRLF + HTML_CRLF )
            else :
                body.append( JIRA_SCA_ISSUE_BODY.format( cxscaticket.severity.upper(), cxscaticket.packagename ) + HTML_CRLF + HTML_CRLF )
            if cxscaticket.description :
                body.append( cxscaticket.description.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF + HTML_CRLF )
        elif scanner == 'kics' :
            cxkicsticket: cxkicsresult = ticket
            if branch :
                body.append( JIRA_KICS_ISSUE_BODY_WITH_BRANCH.format( cxkicsticket.queryname, cxkicsticket.filename, branch ) + HTML_CRLF + HTML_CRLF )
            else :
                body.append( JIRA_KICS_ISSUE_BODY.format( cxkicsticket.queryname, cxkicsticket.filename ) + HTML_CRLF + HTML_CRLF )
            if cxkicsticket.description :
                body.append( cxkicsticket.description.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF + HTML_CRLF )

        ftext = self.cxparams.repo_url
        if ftext and ('gitlab-ci-token' in ftext) and ('@' in ftext) :
            repourl = ftext[:8] + ftext[ftext.find('@')+1:]
        else :
            repourl = ftext

        cxprojectname: str  = self.cxparams.cxproject
        if not cxprojectname :
            cxprojectname = self.scaninfo.projectname

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
        if ticket.highestseverity :
            body.append( '*Severity:* ' + ticket.highestseverity + HTML_CRLF )
 
        body.append( HTML_CRLF )
        body.append( '*Additional Info*' + HTML_CRLF )
        body.append( '----' + HTML_CRLF )
        
        if scanner == 'sast' :
            # Construct references
            if cxsastticket.cwe and cxsastticket.queryid :
                advice_url = self.cxparams.cxurl + '/results/' + self.scaninfo.projectid + '/' + self.scaninfo.scanid + '/sast/description/' + str(cxsastticket.cwe) + '/' + str(cxsastticket.queryid)
            else :
                advice_url = None
            if advice_url :
                body.append( '[Recommended Fix|' + advice_url + ']' + HTML_CRLF )
            if self.cxparams.wiki_url :
                body.append( '[Guidance|' + self.cxparams.wiki_url + ']' + HTML_CRLF)
            if self.cxparams.mitre_url and cxsastticket.cwe :
                body.append( '[Mitre Details|' + self.cxparams.mitre_url % (str(cxsastticket.cwe)) + ']' + HTML_CRLF)
            items_on  = []
            items_off = []                
            for item in cxsastticket.occurences :
                if item.state.lower() == 'not_exploitable' :
                    items_off.append( item.line )
                else :
                    items_on.append( item.line )
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
            if cxsastticket.occurences[0].cxonelink :
                body.append( '[Checkmarx|' + cxsastticket.occurences[0].cxonelink + ']' + HTML_CRLF)
                    
        elif scanner == 'sca' :
            if cxscaticket.id :
                body.append( 'Vulnerability ID: ' + cxscaticket.id + HTML_CRLF)
            if cxscaticket.packagename :
                body.append( 'Package Name: ' + cxscaticket.packagename.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if cxscaticket.packagerepository :
                body.append( 'Package Repo: ' + cxscaticket.packagerepository.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if cxscaticket.cvss :
                body.append( 'CVSS Score: ' + str(cxscaticket.cvss) + HTML_CRLF)
            if cxscaticket.cve :
                body.append( 'CVE: ' + str(cxscaticket.cve) + HTML_CRLF)
            if cxscaticket.releasedate :
                body.append( 'Publish Date: ' + cxscaticket.releasedate + HTML_CRLF)
            if cxscaticket.packageversion :
                body.append( 'Current Package Version: ' + cxscaticket.packageversion.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if cxscaticket.recommendedversion :
                body.append( 'Remediation Upgrade Recommendation: ' + cxscaticket.recommendedversion.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if cxscaticket.newestversion :
                body.append( 'Latest Package Version: ' + cxscaticket.newestversion.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if cxscaticket.packagerepository and cxscaticket.packagename and cxscaticket.packageversion :
                url = self.cxparams.cxurl + '/sca/#/appsec-knowledge-center/package' + \
                    parse.quote(cxscaticket.packagerepository, safe = '') + '/' + \
                    parse.quote(cxscaticket.packagename, safe = '') + '/' + \
                    parse.quote(cxscaticket.packageversion, safe = '')
                body.append( '[Guidance|' + url + ']' + HTML_CRLF)
            if cxscaticket.id.upper().startswith('CVE-') :
                url = 'https://nvd.nist.gov/vuln/detail/' + cxscaticket.id.upper().strip()
                body.append( '[Reference – NVD link|' + url + ']' + HTML_CRLF)
            if cxscaticket.cxonelink :
                body.append( '[Checkmarx|' + cxscaticket.cxonelink + ']' + HTML_CRLF)

        elif scanner == 'kics' :
            if cxkicsticket.platform :
                body.append( 'Platform: ' + cxkicsticket.platform.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if cxkicsticket.issuetype :
                body.append( 'Issue Type: ' + cxkicsticket.issuetype.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if cxkicsticket.occurences[0].actualvalue :
                body.append( 'Current Value: ' + cxkicsticket.occurences[0].actualvalue.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            if cxkicsticket.occurences[0].expectedvalue :
                body.append( 'Expected Value: ' + cxkicsticket.occurences[0].expectedvalue.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF)
            items_on  = []
            items_off = []                
            for item in cxkicsticket.occurences :
                if item.state.lower() == 'not_exploitable' :
                    items_off.append( item.line )
                else :
                    items_on.append( item.line )
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
            if cxkicsticket.occurences[0].cxonelink :
                body.append( '[Checkmarx|' + cxkicsticket.occurences[0].cxonelink + ']' + HTML_CRLF)

        body.append( HTML_CRLF )
        if self.jiraparams.descriptionpostfix :
            body.append( self.jiraparams.descriptionpostfix + HTML_CRLF )
        data = ''.join(body)
        return data[:JIRA_MAX_DESCRIPTION]
    

    
    # Body constructed cxone feed-back apps model
    def __constructbody_cxone( self, scanner: str, ticket: cxresult ) :
        
        body    = []
            
        if self.jiraparams.descriptionprefix :
            body.append( self.jiraparams.descriptionprefix + HTML_CRLF )

        # Resolve project name and branch (special characters handling)
        project_name    = self.scaninfo.projectname.replace('*', ' ').rstrip(HTML_CRLF).strip()
        project_branch  = self.scaninfo.branch.replace('*', ' ').rstrip(HTML_CRLF).strip()

        project_url     = self.cxparams.cxurl + '/projects/' + self.scaninfo.projectid + '/overview?branch=' + project_branch
        scan_url        = self.cxparams.cxurl + '/projects/' + self.scaninfo.projectid + '/scans?id=' + self.scaninfo.scanid + '&branch=' + project_branch
        
        if scanner == 'sast' :
            cxsastticket: cxsastresult = ticket
            # Construct references
            if cxsastticket.cwe and cxsastticket.queryid :
                advice_url = self.cxparams.cxurl + '/results/' + self.scaninfo.projectid + '/' + self.scaninfo.scanid + '/sast/description/' + str(cxsastticket.cwe) + '/' + str(cxsastticket.queryid)
            else :
                advice_url = None
            body.append( '*Checkmarx (SAST):* ' + cxsastticket.queryname + HTML_CRLF )
            if advice_url :
                body.append( '*Security Issue:* [Read More|' + advice_url + '] about ' + cxsastticket.queryname + HTML_CRLF )
            body.append( '*Checkmarx Project:* [' + project_name + '|' + project_url + ']' + HTML_CRLF )
            body.append( '*Branch:* ' + project_branch + HTML_CRLF )
            body.append( '*Scan ID:* [' + self.scaninfo.scanid + '|' + scan_url + ']' + HTML_CRLF )
            # Add description
            body.append( '----' + HTML_CRLF )
            if cxsastticket.description :
                body.append( cxsastticket.description.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
            # Process ocurrences
            occurencecount = 0
            for occurrence in cxsastticket.occurences :
                occurencecount += 1
                body.append( HTML_CRLF + '*Result ' + str(occurencecount) + ':*' + HTML_CRLF )
                body.append( '*Severity:* ' + occurrence.severity + HTML_CRLF )
                body.append( '*State:* ' + occurrence.state + HTML_CRLF )
                body.append( '*Status:* ' + occurrence.status + HTML_CRLF )
                if len(occurrence.nodes) > 0 :
                    nodescount = 0
                    body.append( '*Attack Vector:*' +  HTML_CRLF + HTML_CRLF )
                    for node in occurrence.nodes :
                        nodescount += 1
                        body.append( '*' + str(nodescount) + '. ' + node.name + ':* [' + node.filename + '[' + str(node.line) + ',' + str(node.column) + ']|#L' + str(node.line) + ']' + HTML_CRLF )
                if occurrence.cxonelink :
                    body.append( 'Review result in Checkmarx One: [' + cxsastticket.queryname + '|' + occurrence.cxonelink + ']' + HTML_CRLF )

        elif scanner == 'sca' :
            cxscaticket: cxscaresult = ticket
            advice_url = 'https://devhub.checkmarx.com/cve-details/' + cxscaticket.id
            body.append( '*Checkmarx (SAST):* Vulnerable Package' + HTML_CRLF )
            if advice_url :
                body.append( '*Security Issue:* [Read More|' + advice_url + '] about ' + cxscaticket.id + HTML_CRLF )
            body.append( '*Checkmarx Project:* [' + project_name + '|' + project_url + ']' + HTML_CRLF )
            body.append( '*Branch:* ' + project_branch + HTML_CRLF )
            body.append( '*Scan ID:* [' + self.scaninfo.scanid + '|' + scan_url + ']' + HTML_CRLF )
            # Add description
            if cxscaticket.description :
                body.append( '----' + HTML_CRLF )
                body.append( cxscaticket.description.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
            body.append( '*Additional Info*' + HTML_CRLF )
            if cxscaticket.attackvector :
                body.append( '*Attack vector:* ' + cxscaticket.attackvector + HTML_CRLF )
            if cxscaticket.attackcomplexity :
                body.append( '*Attack complexity:* ' + cxscaticket.attackcomplexity + HTML_CRLF )
            if cxscaticket.confidentiality :
                body.append( '*Confidentiality impact:* ' + cxscaticket.confidentiality + HTML_CRLF )
            if cxscaticket.availability :
                body.append( '*Availability impact:* ' + cxscaticket.availability + HTML_CRLF )
            if cxscaticket.recommendedversion :
                body.append( '*Remediation upgrade recommendation:* ' + cxscaticket.recommendedversion + HTML_CRLF )
            if cxscaticket.cxonelink :
                body.append( 'Review result in Checkmarx One: [' + cxscaticket.id + '|' + cxscaticket.cxonelink + ']' + HTML_CRLF )
                
        elif scanner == 'kics' :
            cxkicsticket: cxkicsresult = ticket
            body.append( '*Checkmarx (IaC Security):* ' + cxkicsticket.queryname + HTML_CRLF )
            body.append( '*Checkmarx Project:* [' + project_name + '|' + project_url + ']' + HTML_CRLF )
            body.append( '*Branch:* ' + project_branch + HTML_CRLF )
            body.append( '*Scan ID:* [' + self.scaninfo.scanid + '|' + scan_url + ']' + HTML_CRLF )
            if cxkicsticket.description :
                body.append( cxkicsticket.description.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
            # Process ocurrences
            body.append( HTML_CRLF + '*Locations:*' + HTML_CRLF )
            occurencecount = 0
            for occurrence in cxkicsticket.occurences :
                occurencecount += 1
                body.append( HTML_CRLF + '*Result ' + str(occurencecount) + ':*' + HTML_CRLF )
                body.append( '*Severity:* ' + occurrence.severity + HTML_CRLF )
                body.append( '*State:* ' + occurrence.state + HTML_CRLF )
                body.append( '*Status:* ' + occurrence.status + HTML_CRLF )
                body.append( '*File:* ' + '[' + occurrence.filename + '[' + str(occurrence.line) + ',0]|#L' + str(occurrence.line) + ']' + HTML_CRLF )
                body.append( '*Expected value:* ' + occurrence.expectedvalue.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
                body.append( '*Actual value:* ' + occurrence.actualvalue.replace('*', ' ').rstrip(HTML_CRLF).strip() + HTML_CRLF )
                if occurrence.cxonelink :
                    body.append( 'Review result in Checkmarx One: [' + cxkicsticket.queryname + '|' + occurrence.cxonelink + ']' + HTML_CRLF )
        
        body.append( HTML_CRLF )
        if self.jiraparams.descriptionpostfix :
            body.append( self.jiraparams.descriptionpostfix + HTML_CRLF )
        data = ''.join(body)
        return data[:JIRA_MAX_DESCRIPTION]
    
    
    
    def __constructbody( self, scanner: str, ticket: cxresult ) :
        # if self.cxparams.legacymode :
        if self.cxparams.contentstyle.lower() == 'legacy' :
            return self.__constructbody_legacy( scanner, ticket )
        else :
            return self.__constructbody_cxone( scanner, ticket )
    
    
    
    def __contructlabels( self, scanner: str, ticket: cxresult ) :
        labels = []
    
        if self.cxparams.legacymode :
            labels.append( self.JIRA_CX_PRODUCT )
            if scanner == 'sast' :
                labels.append( self.JIRA_ISSUE_LABEL_SAST )
            elif scanner == 'sca' :
                cxscaticket: cxscaresult = ticket
                labels.append( self.JIRA_ISSUE_LABEL_SCA )
                if cxscaticket.isdev :
                    labels.append( JIRA_SCA_DEV_LABEL )
                elif cxscaticket.istest :
                    labels.append( JIRA_SCA_TEST_LABEL )
                else :
                    labels.append( JIRA_SCA_PROD_LABEL )
            elif scanner == 'kics' :
                labels.append( self.JIRA_ISSUE_LABEL_KICS )
            # From params, namespace and application and repo provided
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
            
        else :    
            labels.append( self.JIRA_CX_PRODUCT )
            if scanner == 'sast' :
                labels.append( self.JIRA_ISSUE_LABEL_SAST )
            elif scanner == 'sca' :
                labels.append( self.JIRA_ISSUE_LABEL_SCA )
            elif scanner == 'kics' :
                labels.append( self.JIRA_ISSUE_LABEL_KICS )
            labels.append( self.jiraparams.branchlabelprefix + ':' + self.scaninfo.branch )
            if self.cxparams.namespace :
                labels.append( self.jiraparams.ownerlabelprefix + ':' + self.cxparams.namespace )
            else :
                labels.append( self.jiraparams.ownerlabelprefix + ':n/a' )
            labels.append( self.jiraparams.projectlabelprefix + ':' + self.scaninfo.projectname )
            if self.cxparams.repository :
                labels.append( self.jiraparams.repolabelprefix + ':' + self.cxparams.repository )
            else :
                labels.append( self.jiraparams.repolabelprefix + ':' + self.scaninfo.projectname )
            
        return labels
        
        
        
    def __constructfieldsmappings( self, scanner: str, ticket: cxresult, labels: list, existingjiraticket = None ) :
        fields = []

        cxprojectname: str  = self.cxparams.cxproject
        if not cxprojectname :
            cxprojectname = self.scaninfo.projectname

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

            updateoperation = None            
            if not existingjiraticket :
                updateoperation = 'new'
            elif existingjiraticket and (jiraname.lower() != 'labels') and jirago :
                if 'set' in operations :
                    updateoperation = 'set'
                if not updateoperation :
                    cxlogger.logdebug( 'Skip update to field "' + jiralabel + '"' )
                    
            if (not updateoperation) and (jiraname.lower() == 'labels') and jirago :
                updateoperation = 'label'

            if not updateoperation :
                jirago = False

            if jirago:

                # Custom fields/tags
                if ftype == 'cx' :

                    # Custom fields/tags from scan
                    if fname == 'cx-scan' :
                        fieldvalue = self.scaninfo.tagstext
                        if not fieldvalue and jiradefault :
                            fieldvalue = jiradefault
                        else :
                            fieldvalue = None
                    # Custom fields/tags from project
                    else :
                        ftag    = next( filter( lambda el: el['name'].lower() == fname.lower(), self.scaninfo.projecttags ), None )
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
                    elif fname == 'site' :
                        fieldvalue = self.cxparams.cxurl
                    elif fname == 'system-date' :
                        date = datetime.now()
                        if jiraoffset and jiraoffset != 0 :
                            date = date + datetime.timedelta(days = jiraoffset)
                        fieldvalue = date.strftime('%Y-%m-%d')
                    elif fname == 'severity' :
                        fieldvalue = ticket.highestseverity

                    # SAST result
                    if scanner == 'sast' :
                        cxsastticket: cxsastresult = ticket
                        if fname == 'issue-link' :
                            fieldvalue = cxsastticket.occurences[0].cxonelink
                        elif fname == 'comment' :
                            fieldvalue = cxsastticket.occurences[0].comment
                        elif fname == 'similarity-id' :
                            fieldvalue = cxsastticket.occurences[0].similarityid
                        elif fname == 'not-exploitable' :
                            ftext = []
                            for item in cxsastticket.occurences :
                                if item.state.lower() == 'not_exploitable' :
                                    ftext.append(str(item.line))
                            if len(ftext) > 0 :
                                fieldvalue = ','.join(ftext)
                        elif fname == 'category' :
                            fieldvalue = cxsastticket.queryname
                        elif fname == 'cwe' :
                            fieldvalue = cxsastticket.cwe
                        elif fname == 'recommendation' :
                            ftext = []
                            advice_url = None
                            if cxsastticket.cwe and cxsastticket.queryid :
                                advice_url = self.cxparams.cxurl + '/results/' + self.scaninfo.projectid + '/' + self.scaninfo.scanid + '/sast/description/' + str(cxsastticket.cwe) + '/' + str(cxsastticket.queryid)
                            if advice_url :
                                ftext.append( 'Advice: ' + advice_url )
                            if self.cxparams.mitre_url and cxsastticket.cwe :
                                txt = self.cxparams.mitre_url % (str(cxsastticket.cwe))
                                ftext.append( 'Mitre Details: ' + txt )
                            if self.cxparams.wiki_url :
                                ftext.append( 'Guidance: ' + self.cxparams.wiki_url )
                            if len(ftext) > 0 :
                                fieldvalue = HTML_CRLF.join(ftext)
                        elif fname == 'loc' :
                            fieldvalue = self.scaninfo.loc
                        elif fname == 'filename' :
                            fieldvalue = cxsastticket.filename
                        elif fname == 'language' :
                            fieldvalue = cxsastticket.language
                                
                        
                    # SCA result
                    elif scanner == 'sca' :
                        cxscaticket: cxscaresult = ticket
                        if fname == 'issue-link' :
                            fieldvalue = cxscaticket.cxonelink
                        elif fname == 'comment' :
                            fieldvalue = cxscaticket.comment
                        elif fname == 'similarity-id' :
                            fieldvalue = cxscaticket.similarityid
                        elif fname == 'not-exploitable' :
                            if cxscaticket.state.lower() == 'not_exploitable' :
                                fieldvalue = 'yes'
                        elif fname == 'package-name' :
                            fieldvalue = cxscaticket.packagename
                        elif fname == 'current-version' :
                            fieldvalue = cxscaticket.packageversion
                        elif fname == 'fixed-version' :
                            fieldvalue = cxscaticket.recommendedversion
                        elif fname == 'newest-version' :
                            fieldvalue = cxscaticket.newestversion
                        elif fname == 'dev-dependency' :
                            if cxscaticket.isdev :
                                fieldvalue = 'TRUE'
                            else :
                                fieldvalue = 'FALSE'
                        elif fname == 'test-dependency' :
                            if cxscaticket.istest :
                                fieldvalue = 'TRUE'
                            else :
                                fieldvalue = 'FALSE'
                        elif fname == 'direct-dependency' :
                            if cxscaticket.relation.upper() == 'DIRECT' :
                                fieldvalue = 'TRUE'
                            else :
                                fieldvalue = 'FALSE'
                        elif fname == 'risk-score' :
                            fieldvalue = cxscaticket.cvss
                        elif fname == 'outdated' :
                            if cxscaticket.packageversion == cxscaticket.newestversion :
                                fieldvalue = 'FALSE'
                            else :
                                fieldvalue = 'TRUE'
                        elif fname == 'violates-policy' :
                            if cxscaticket.violatedpolicies :
                                fieldvalue = 'TRUE'
                            else :
                                fieldvalue = 'FALSE'
                        elif fname == 'cve' :
                            fieldvalue = cxscaticket.cve
                                
                    # KICS result
                    elif scanner == 'kics' :
                        cxkicsticket: cxkicsresult = ticket
                        if fname == 'issue-link' :
                            fieldvalue = cxkicsticket.occurences[0].cxonelink
                        elif fname == 'comment' :
                            fieldvalue = cxkicsticket.occurences[0].comment
                        elif fname == 'similarity-id' :
                            fieldvalue = cxkicsticket.occurences[0].similarityid
                        elif fname == 'not-exploitable' :
                            ftext = []
                            for item in cxkicsticket.occurences :
                                if item.state.lower() == 'not_exploitable' :
                                    ftext.append(str(item.line))
                            if len(ftext) > 0 :
                                fieldvalue = ','.join(ftext)

                        elif fname == 'category' :
                            fieldvalue = cxkicsticket.queryname
                        elif fname == 'platform' :
                            fieldvalue = cxkicsticket.platform
                        elif fname == 'filename' :
                            fieldvalue = cxkicsticket.occurences[0].filename
                        elif fname == 'issue-type' :
                            fieldvalue = cxkicsticket.issuetype
                        elif fname == 'recommendation' :
                            fieldvalue = cxkicsticket.occurences[0].expectedvalue

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
                                if (jiralabel == '') or (jiralabel == self.jiraparams.labeltracker) :
                                    labels.append( ''.join(xvalue))
                                else :
                                    labels.append( jiralabel + ':' + ''.join(xvalue) )
                            else :
                                fields.append( { jiraname : xvalue } )
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
        


    def __processjiraexception( self, creating: bool, retrieving: bool, he: HTTPError ) :
        jdata = json.loads(he.response.text)
        smsg  = ''
        if 'errors' in jdata :
            txt = []
            for error in jdata['errors'].keys() :
                txt.append( jdata['errors'][error] + ' (' + error + ')' )
            if len(txt) == 0 and 'errorMessages' in jdata :
                for error in jdata['errorMessages'] :
                    txt.append( error )
            smsg = ', '.join(txt)
        if not smsg :
            if retrieving :
                smsg = 'Error retrieving jira tickets'
            elif creating :
                smsg = 'Error creating jira ticket'
            else :
                smsg = 'Error updating jira ticket'
        else : 
            if retrieving :
                smsg = 'Error retrieving jira tickets, ' + smsg
            elif creating :
                smsg = 'Error creating jira ticket, ' + smsg
            else :
                smsg = 'Error updating jira ticket, ' + smsg
        return smsg
            
    
    
    def __processjiraticket( self, scanner: str, ticketsummary: str, ticket: cxresult, jiraticket = None ) :
        
        # Construct description (body) according to legacymode
        description = self.__constructbody( scanner, ticket )
        
        # Construct priority
        priority = None
        if len(self.jiraparams.priorities) > 0 :
            severity = ticket.highestseverity.upper()
            if severity == 'INFORMATIONAL' :
                priority = self.jiraparams.priorities.get('INFO')
            else :
                priority = self.jiraparams.priorities.get(severity)        
    
        # Contruct labels
        labels = self.__contructlabels( scanner, ticket )
        
        # Contruct field mappings
        fields = self.__constructfieldsmappings( scanner, ticket, labels, jiraticket )
        # Make sure labels are unique
        labels = list(set(labels))
        
        # Does the issue exist ?
        if not jiraticket :
            try :            
                jiraticket = self.jira.projectcreateissue( self.jiraparams.projectid, self.jiraparams.issuetypeid, ticketsummary, description, fields, labels, priority )
            except HTTPError as e:
                raise Exception( self.__processjiraexception( True, False, e ) )
            except Exception as e:
                if str(e) :
                    raise e
                else :
                    raise Exception( 'Error creating jira ticket' )
            
            # Add to CREATED
            cxlogger.verbose( '- JIRA issue ' + jiraticket.get('key') + ' created, type ' + scanner.upper() + ', with key "' + ticketsummary + '"' )
        else :
        
            ticketkey = jiraticket.get('key')
            current_status = jiraticket['fields']['status']['name']
            reopened = False
            # If it's not opened, let's reopen it
            if (str(current_status).lower() in self.jiraparams.closedstatus) :
                if self.jiraparams.opentransition :
                    try :
                        retdata = self.jira.tickettransition( ticketkey, self.jiraparams.opentransition )
                    except HTTPError as e:
                        raise Exception( self.__processjiraexception( False, False, e ) )
                    except Exception as e:
                        if str(e) :
                            raise e
                        else :
                            raise Exception( 'Error transitioning jira ticket' )
                    
                    reopened = True
                else :
                    cxlogger.logwarning( 'Open transtion missing. Cannot reopen "' + str(ticketkey) + '"' )
            # Check if description changed
            newdescription = None
            if description and (not description == jiraticket['fields'].get('description')) :
                newdescription = description
            # Check if priority changed
            newpriority = None
            ticketpriority = None
            if jiraticket['fields'].get('priority') :
                ticketpriority = jiraticket['fields']['priority'].get('name')
            if priority and (not priority == ticketpriority) :
                newpriority = priority
            # Check if labels changed
            newlabels   = []
            existinglabels = jiraticket['fields'].get('labels')
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
                try :
                    self.jira.projecteditissue( ticketkey, newdescription, fields, newlabels, newpriority )
                except HTTPError as e:
                    raise Exception( self.__processjiraexception( False, False, e ) )
                except Exception as e:
                    if str(e) :
                        raise e
                    else :
                        raise Exception( 'Error updating jira ticket' )

            if reopened :
                cxlogger.verbose( '- JIRA issue ' + ticketkey + ' re-opened, type ' + scanner.upper() + ', prev status "' + current_status + '", with key "' + ticketsummary + '"' )
            else :
                cxlogger.verbose( '- JIRA issue ' + ticketkey + ' still exists, type ' + scanner.upper() + ', status "' + current_status + '", with key "' + ticketsummary + '"' )
        
        return jiraticket
        


    def __processscannerresults( self, scanner: str ) :

        # Get existing jira tickets for scanner
        cxlogger.verbose( 'Check existing ' + scanner + ' tickets' )
        jiratickets = self.__retrievejiratickets( scanner ) 
        if len(jiratickets) == 0 :
            cxlogger.verbose( '- No existing ' + scanner + ' tickets found' )
        else :
            cxlogger.verbose( '- Found ' + str(len(jiratickets)) + ' ' + scanner + ' tickets' )
            
        # Identify the results list
        resultslist = None        
        if scanner == 'sast' :
            resultslist = self.results.sast
        elif scanner == 'sca' :
            resultslist = self.results.sca
        elif scanner == 'kics' :
            resultslist = self.results.kics
        if not resultslist :
            return    
        
        # Check closed tickets
        for jiraticket in jiratickets :
            jiraticketsummary   = jiraticket['fields'].get('summary')
            jiraticketkey       = jiraticket.get('key')
            jirastatus          = jiraticket['fields']['status']['name']
            # Does the result still exist ?
            cxresult = None
            for ticket in resultslist :
                ticketsummary = self.__getsummary( scanner, ticket )    
                if ticketsummary == jiraticketsummary :
                    cxresult = ticket
                    break
            # Shall close it ?
            if not cxresult and (str(jirastatus).lower() in self.jiraparams.openstatus) :
                if self.jiraparams.closetransition :
                    self.jira.tickettransition( jiraticketkey, self.jiraparams.closetransition )
                    cxlogger.verbose( '- JIRA issue ' + str(jiraticketkey) + ' closed, type ' + scanner.upper() + ', prev status "' + str(jirastatus) + '", with key "' + jiraticketsummary + '"' )
                else :
                    cxlogger.logwarning( 'Close transtion missing. Cannot close "' + str(jiraticketkey) + '"' )
        
        # Check new or updated tickets
        for ticket in resultslist :
            ticketsummary = self.__getsummary( scanner, ticket )
            # Does the ticket exist ?
            jiraticket = next( filter( lambda el: el['fields']['summary'] == ticketsummary, jiratickets ), None )
            # Will create, update, and transition (open/close/reopen)
            self.__processjiraticket( scanner, ticketsummary, ticket, jiraticket )



    # Override
    def processfeedback(self) : 

        # Establish connection to Jira and pre-process Jira parameters
        self.__initialize()
        # Setup references and constants (legacymode or cxone mode)
        self.__intreferences()
        # Process tags (project and scan) to fields, when content style is not legacy mode
        if self.cxparams.contentstyle == 'cxone' :
            # Process project tags first
            self.__processtagfields( projecttags = True ) 
            # Process scan tags next
            self.__processtagfields( projecttags = False ) 

        # Go one scanner at the time
        if len(self.results.sast) > 0 :
            self.__processscannerresults( 'sast' )
        if len(self.results.sca) > 0 :
            self.__processscannerresults( 'sca' )
        if len(self.results.kics) > 0 :
            self.__processscannerresults( 'kics' )

        return