""" 
========================================================================

CLASS TO JIRA REST INTERACTIONS
Requires:   atlassian-python-api
            pip install atlassian-python-api
References: https://docs.atlassian.com/software/jira/docs/api/REST/8.5.0/#api/2
            https://community.atlassian.com/t5/Jira-articles/Atlassian-Python-API-s/ba-p/2091355
            https://community.atlassian.com/t5/App-Central/Basics-of-API-in-Jira-Confluence-and-Bitbucket/ba-p/1599968
            https://developer.atlassian.com/server/jira/platform/jira-rest-api-examples

========================================================================
"""

from urllib import parse
from atlassian import Jira


class cxjiraapi(object) :

    def __init__(self) :
        self.__jiraintf: Jira   = None
        self.__jiraurl: str     = None
        self.__jirausr: str     = None
        self.__jirakey: str     = None
        self.__jiracloud: bool  = True
        self.__jiraverssl: bool = True
        self.__jiratimeout: int = None
        self.__proxyurl: str    = None
        self.__proxyuser: str   = None
        self.__proxypass: str   = None


    def __init__(self, fqdn: str, username: str, apikey: str, iscloud: bool = False, verifyssl: bool = True, timeout: int = None, proxy_url: str = None, proxy_username: str = None, proxy_password: str = None ) :
        self.__jiraintf: Jira   = None
        self.__jiraurl: str     = fqdn
        self.__jirausr: str     = username
        self.__jirakey: str     = apikey
        self.__jiracloud: bool  = iscloud  
        self.__jiraverssl: bool = verifyssl
        self.__jiratimeout: int = timeout
        self.__proxyurl: str    = proxy_url
        self.__proxyuser: str   = proxy_username
        self.__proxypass: str   = proxy_password



    @property
    def jira(self) :
        if not self.__jiratimeout :
            time_out = 10000
        else :
            time_out = self.__jiratimeout
        if not self.__jiraintf :
            proxyurl    = None
            proxyhosts  = None
            # Check proxy
            if self.__proxyurl :
                proxyurl = self.__proxyurl.lower()
                if self.__proxyuser or self.__proxypass :
                    proxyprotocol = ''
                    proxyendpoint = proxyurl
                    sep = proxyurl.find('://')
                    if sep > 0 :
                        proxyprotocol = proxyurl[0:sep+3]
                        proxyendpoint = proxyurl[sep+3:]
                        proxyurl = proxyprotocol + parse.quote(self.__proxyuser, safe = '') + ':' + parse.quote(self.__proxypass, safe = '') + '@' + proxyendpoint
                proxyhosts  = { 'http': proxyurl, 'https': proxyurl }
                # Check PAT or basic auth
                if not self.__jirausr :
                    self.__jiraintf = Jira( url = self.__jiraurl, token = self.__jirakey, cloud = self.__jiracloud, verify_ssl = self.__jiraverssl, proxies = proxyhosts, timeout = time_out )
                else :
                    self.__jiraintf = Jira( url = self.__jiraurl, username = self.__jirausr, password = self.__jirakey, cloud = self.__jiracloud, verify_ssl = self.__jiraverssl, proxies = proxyhosts, timeout = time_out )
            else :
                # Check PAT or basic auth
                if not self.__jirausr :
                    self.__jiraintf = Jira( url = self.__jiraurl, token = self.__jirakey, cloud = self.__jiracloud, verify_ssl = self.__jiraverssl, timeout = time_out )
                else :
                    self.__jiraintf = Jira( url = self.__jiraurl, username = self.__jirausr, password = self.__jirakey, cloud = self.__jiracloud, verify_ssl = self.__jiraverssl, timeout = time_out )
        return self.__jiraintf
    

    def serverinfo(self):
        data = self.jira.get_server_info()
        # Version string in the format: 9.16.0
        # Deployment type string of "", "Server", "DataCenter" 
        return data['version'], data['deploymentType']      


    def jql(self, jqlquery: str, fields: str = '*all', start: int = 0, limit = None, expand = None, validate_query = None ) :
        data = self.jira.jql( jqlquery, fields, start, limit, expand, validate_query )
        return data


    def projects(self) :
        return self.jira.projects()
    

    def project(self, projectkey ) :
        return self.jira.project( key = projectkey )


    def projectissuetypes(self, projectkey) :
        data = self.jira.project( key = projectkey )
        return data['issueTypes']
        

    def projectissuefields(self, projectkey, issuetypekey) :
        data = []
        found = False
        # Try using jira v9.x api
        if not found :
            try:
                xdata = self.jira.issue_createmeta_fieldtypes( project = projectkey, issue_type_id = issuetypekey )
                if 'fields' in xdata :      # At JIRA cloud
                    data = xdata['fields']
                    found = True
                elif 'values' in xdata :    # At JIRA server
                    data = xdata['values']
                    found = True
            except :
                pass
        # Try using old v8.x api
        if not found :
            try :
                xdata = self.jira.issue_createmeta(self, project = projectkey, expand = "projects.issuetypes.fields")
                if 'projects' in xdata :
                    xissues = xdata['projects']['issuetypes']
                    xissue = next( filter( lambda el: el['id'] == issuetypekey ), None )
                    if xissue and 'fields' in xissue :
                        data = xissue['fields']
                        found = True
            except :
                pass
        if not found :
            raise Exception( 'Unable to detect issue fields. ')
        return data
    

    def projectgetissues( self, projectkey, issuetypekey, extraquery: str = None, pagesize: int = 100 ) :
        issues  = []
        top     = 0
        limit   = pagesize
        if extraquery :
            jql = 'project = ' + str(projectkey) + ' and issuetype = ' + str(issuetypekey) + ' and ( ' + extraquery + ' )'
        else :
            jql = 'project = ' + str(projectkey) + ' and issuetype = ' + str(issuetypekey)
        data = self.jira.jql( jql, start = top, limit = limit )
        while len(data['issues']) > 0 :
            issues.extend(data['issues'])
            top += limit
            data = self.jira.jql( jql, start = top, limit = limit )
        return issues
        # &maxResults=1000
        # http://localhost:8080/rest/api/2/issue/createmeta?projectKeys=JRA&issuetypeNames=Bug&


    def tickettransition( self, ticketid, transition ) :
        # Check issue transitions
        stransitions = self.jira.get_issue_transitions(issue_key = ticketid)
        # Find desired transition id
        transition_id: int = None
        for t in stransitions :
            if t['name'] == transition :
                transition_id = t['id']
        # Move to transition
        return self.jira.set_issue_status_by_transition_id(ticketid, transition_id)


    def projectcreateissue(self, projectkey, issuetypekey, summary: str, description: str, fieldsandvalues: list = None, labels: list = None, priority: str = None ) :

        payload = {}
        # Construct mandatory fields
        payload['project']          = { 'id': projectkey }
        payload['issuetype']        = { 'id': issuetypekey }
        payload['summary']          = summary
        payload['description']      = description
        if priority :
            payload['priority']     = { 'name': priority }
        # Add labels field
        if labels :
            payload['labels'] = labels
        # Add additional fields
        if fieldsandvalues :
            for field in fieldsandvalues :
                fieldname           = list(dict(field).keys())[0]
                fieldValue          = field[fieldname] 
                payload[fieldname]  = fieldValue

        xdata = dict(payload)
        
        data = self.jira.create_issue( fields = xdata )

        return data
        

    def projecteditissue(self, issueid, description: str = None, fieldsandvalues: list = None, labels: list = None, priority: str = None ) :

        payload = {}
        if description :
            payload['description']  = [ { 'set':  description } ]
        if priority :
            payload['priority']     = { 'name': priority }
        # Add labels field
        if labels :
            xlabels = []
            for label in labels :
                xlabels.append( { 'add': label } )
            payload['labels'] = xlabels
        # Add additional fields
        if fieldsandvalues :
            for field in fieldsandvalues :
                fieldname           = list(dict(field).keys())[0]
                fieldValue          = field[fieldname] 
                payload[fieldname]  = [ { 'set' : fieldValue } ]
                
        xdata = dict(payload)

        data = self.jira.edit_issue( issue_id_or_key = issueid, fields = xdata )

        return data
    


    def projectdeleteissue(self, issueid ) :
        data = self.jira.delete_issue( issue_id_or_key = issueid )
        return data