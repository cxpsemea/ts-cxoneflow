""" 
========================================================================

SIMPLE CLASS TO JIRA INTERACTIONS
Requires:   atlassian-python-api
            pip install atlassian-python-api
References: https://docs.atlassian.com/software/jira/docs/api/REST/8.5.0/#api/2
            https://community.atlassian.com/t5/Jira-articles/Atlassian-Python-API-s/ba-p/2091355
            https://community.atlassian.com/t5/App-Central/Basics-of-API-in-Jira-Confluence-and-Bitbucket/ba-p/1599968
            https://developer.atlassian.com/server/jira/platform/jira-rest-api-examples

joao.costa@checkmarx.com
PS-EMEA
20-12-2023

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
        self.__jiratimeout: int = None
        self.__proxyurl: str    = None
        self.__proxyuser: str   = None
        self.__proxypass: str   = None


    def __init__(self, fqdn: str, username: str, apikey: str, iscloud: bool = True, timeout: int = None, proxy_url: str = None, proxy_username: str = None, proxy_password: str = None ) :
        self.__jiraintf: Jira   = None
        self.__jiraurl: str     = fqdn
        self.__jirausr: str     = username
        self.__jirakey: str     = apikey
        self.__jiracloud: bool  = iscloud  
        self.__jiratimeout: int = timeout
        self.__proxyurl: str    = proxy_url
        self.__proxyuser: str   = proxy_username
        self.__proxypass: str   = proxy_password



    @property
    def jira(self) :
        if not self.__jiratimeout :
            time_out = 1000
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
                self.__jiraintf = Jira( url = self.__jiraurl, username = self.__jirausr, password = self.__jirakey, cloud = self.__jiracloud, proxies = proxyhosts, timeout = time_out )
            else :
                self.__jiraintf = Jira( url = self.__jiraurl, username = self.__jirausr, password = self.__jirakey, cloud = self.__jiracloud, timeout = time_out )
        return self.__jiraintf
    

    # def checkpermissions(self) :



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
        data = self.jira.issue_createmeta_fieldtypes( project = projectkey, issue_type_id = issuetypekey )
        return data['fields']
    

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
        return self.jira.issue_transition( issue_key = ticketid, status = transition )


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