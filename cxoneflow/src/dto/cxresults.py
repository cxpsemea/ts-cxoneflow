
from urllib import parse


# Helper, base class
class cxresult(object) :
    
    def __init__(self) :
        self.highestseverity: str   = None
        self.engine: str            = None
        return
    
    def check_highestseverity( self, newseverity: str ) :
        if not self.highestseverity :
            self.highestseverity = newseverity
        else :
            curr = self.highestseverity.upper()
            new  = newseverity.upper()
            if curr != new :
                icurr: int = 0
                # Cur
                if curr == 'LOW' :
                    icurr = 1
                elif curr == 'MEDIUM' :
                    icurr = 2
                elif curr == 'HIGH' :
                    icurr = 3
                elif curr == 'CRITICAL' :
                    icurr = 4
                else :
                    icurr = 0
                # New
                if new == 'LOW' and icurr < 1 :
                    self.highestseverity = newseverity
                elif new == 'MEDIUM' and icurr < 2 :
                    self.highestseverity = newseverity
                elif new == 'HIGH' and icurr < 3 :
                    self.highestseverity = newseverity
                elif curr == 'CRITICAL'  and icurr < 4 :
                    self.highestseverity = newseverity
        return self.highestseverity 


class cxsastresultoccourrencenode(object) :
    
    def __init__( self, name: str, filename: str, line: int, column: int ) :
        self.name       = name
        self.filename   = filename
        self.line       = line
        self.column     = column

class cxsastresultoccourence(object) :
    
    def __init__( self, sastresult, sastresulturlmask: str ) :
        self.id: str                = sastresult['id']
        self.severity: str          = sastresult['severity']
        self.state: str             = sastresult['state']
        self.status: str            = sastresult['status']
        self.similarityid: str      = sastresult['similarityId']
        self.foundat: str           = sastresult['foundAt']
        self.filename: str          = sastresult['data']['nodes'][0]['fileName']
        self.line: int              = sastresult['data']['nodes'][0]['line']
        self.nodes: list[cxsastresultoccourrencenode] = []
        self.resulthash: str        = sastresult['data']['resultHash']
        self.comment: str           = sastresult['comments'].get('comments') if sastresult['comments'] else ''
        self.cxonelink: str         = sastresulturlmask.format(resultid = parse.quote(sastresult['data']['resultHash'], safe = '') ) if sastresult['data']['resultHash'] else None
        # Add the nodes list
        for node in sastresult['data']['nodes'] :
            self.nodes.append( cxsastresultoccourrencenode( node['name'], node['fileName'], node['line'], node['column'] ) )


# One result aggregator
class cxsastresult(cxresult) :
    
    def __init__( self, key: str, sastresult, sastresulturlmask: str ) :
        super().__init__()
        self.engine = 'sast'
        sdescription = ''
        if 'description' in sastresult :
            sdescription = sastresult['description']
        self.key: str               = key
        self.group: str             = sastresult['data']['group']
        self.queryid: str           = sastresult['data']['queryId']
        self.queryname: str         = sastresult['data']['queryName']
        self.language: str          = sastresult['data']['languageName']
        self.filename: str          = sastresult['data']['nodes'][0]['fileName']
        self.cwe: int               = sastresult['vulnerabilityDetails']['cweId']
        self.description: str       = sdescription
        self.occurences: list[cxsastresultoccourence] = []
        self.addoccurence( sastresult, sastresulturlmask )

    def addoccurence( self, sastresult, sastresulturlmask: str ) :
        self.check_highestseverity( sastresult['severity'])
        self.occurences.append( cxsastresultoccourence(sastresult, sastresulturlmask) )
        
                        
                     
class cxscaresult(cxresult) :
    
    def __init__( self, key: str, scaresult, scapackage, scaresulturlmask: str ) :
        super().__init__()
        self.engine = 'sca'
        self.check_highestseverity(scaresult['severity'])
        sdescription = ''
        if 'description' in scaresult :
            sdescription = scaresult['description']
        self.key: str                   = key
        self.id: str                    = scaresult['id']
        self.severity: str              = scaresult['severity']
        self.cvss: float                = scaresult['vulnerabilityDetails']['cvssScore']
        self.cve: str                   = scaresult['vulnerabilityDetails']['cveName']
        self.cwe: str                   = scaresult['vulnerabilityDetails']['cweId']
        self.packageid: str             = scaresult['data']['packageIdentifier']
        # >> From package
        self.packagename: str           = scapackage['name']
        self.packageversion: str        = scapackage['version']
        self.packagerepository: str     = scapackage['packageRepository']
        self.relation: str              = scapackage['relation']
        self.matchtype: str             = scapackage['matchType']
        self.ismalicious: bool          = scapackage['isMalicious']
        self.issupplychain: bool        = False
        if scapackage.get('risks') :
            if scapackage['risks'].get('supplyChainRisks') :
                risks = scapackage['risks']['supplyChainRisks']
                riskcount = risks['critical'] + risks['high'] + risks['medium'] + risks['low']
                if riskcount > 0 :
                    self.issupplychain: bool    = True
        self.isdev: bool                = scapackage['isDev']
        self.istest: bool               = scapackage['isTest']
        self.releasedate: str           = scapackage['releaseDate']
        self.legalrisklevel: str        = scapackage['legalRiskLevel']
        self.dependencypathcount: int   = scapackage['dependencyPathCount']
        self.newestversion: str         = scapackage['outdatedModel']['newestVersion']
        self.newestdate: str            = scapackage['outdatedModel']['newestLibraryDate']
        self.versionsbetween: int       = scapackage['outdatedModel']['versionsInBetween']
        self.violatedpoliciescount: int = scapackage['violatedPoliciesCount']
        self.violatedpolicies: list     = scapackage['violatedPolicies']
        # << From package
        self.recommendedversion: str    = scaresult['data']['recommendedVersion']
        self.description: str           = sdescription
        self.state: str                 = scaresult['state']
        self.status: str                = scaresult['status']
        self.similarityid: str          = scaresult['similarityId']
        self.foundat: str               = scaresult['foundAt']
        self.attackvector: str          = scaresult['vulnerabilityDetails']['cvss'].get('attackVector')
        self.attackcomplexity: str      = scaresult['vulnerabilityDetails']['cvss'].get('attackComplexity')
        self.confidentiality: str       = scaresult['vulnerabilityDetails']['cvss'].get('confidentiality')
        self.availability: str          = scaresult['vulnerabilityDetails']['cvss'].get('availability')
        self.exploitablepath: int       = len(scaresult['data']['exploitableMethods']) if scaresult['data']['exploitableMethods'] else 0
        self.comment: str               = scaresult['comments'].get('comments') if scaresult['comments'] else ''
        self.cxonelink: str             = None
        if not ( self.ismalicious or self.issupplychain ) :
            urlresultid = parse.quote('/vulnerabilities/' + parse.quote(self.id + ':' + self.packageid, safe = '') + '/vulnerabilityDetailsGql', safe = '')
            self.cxonelink              = scaresulturlmask.format(resultid = urlresultid)
        


class cxkicsresultoccurence(object) :
    
    def __init__( self, kicsresult, kicsresulturlmask: str ) :
        self.id: str                = kicsresult['ID']
        self.severity: str          = kicsresult['severity']
        self.state: str             = kicsresult['state']
        self.status: str            = kicsresult['status']
        self.similarityid: str      = kicsresult['similarityID']
        self.foundat: str           = kicsresult['foundAt']
        self.filename: str          = kicsresult['fileName']
        self.line: int              = kicsresult['line']
        self.actualvalue: str       = kicsresult['actualValue']
        self.expectedvalue: str     = kicsresult['expectedValue']
        self.resulthash: str        = kicsresult['ID']
        self.comment: str           = kicsresult['comments']
        self.cxonelink: str         = kicsresulturlmask.format(resultid = parse.quote(kicsresult['ID'], safe = '') ) if kicsresult['ID'] else None

                        
class cxkicsresult(cxresult) :
    
    def __init__( self, key: str, kicsresult, kicsresulturlmask: str ) :
        super().__init__()        
        self.engine = 'kics'
        sdescription = ''
        if 'description' in kicsresult :
            sdescription = kicsresult['description']
        self.key: str               = key
        self.group: str             = kicsresult['group']
        self.queryid: str           = kicsresult['queryID']
        self.queryname: str         = kicsresult['queryName']
        self.platform: str          = kicsresult['platform']
        self.issuetype: str         = kicsresult['issueType']
        self.filename: str          = kicsresult['fileName']
        self.category: str          = kicsresult['category']
        self.description: str       = sdescription
        self.occurences: list[cxkicsresultoccurence] = []
        self.addoccurence( kicsresult, kicsresulturlmask )

    def addoccurence( self, kicsresult, kicsresulturlmask: str ) :
        self.check_highestseverity( kicsresult['severity'])
        self.occurences.append( cxkicsresultoccurence(kicsresult, kicsresulturlmask) )



# Results aggregator for scanner
class cxresults(object) :
    
    def __init__( self ) :
        
        self.sast: list[cxsastresult]       = []
        self.sca: list[cxscaresult]         = []
        self.kics: list[cxkicsresult]       = []

    def findresult( self, scanner, key ) :
        if scanner == 'sast' :
            return next( filter( lambda el: el.key == key, self.sast), None )
        elif scanner == 'sca' :
            return next( filter( lambda el: el.key == key, self.sca), None )
        elif scanner == 'kics' :
            return next( filter( lambda el: el.key == key, self.kics), None )
        else :
            return None
            
    def addresult( self, scanner, key, result, resulturlmask: str, package = None ) :
        if scanner == 'sast' :
            self.sast.append( cxsastresult(key, result, resulturlmask) )
        elif scanner == 'sca' :
            self.sca.append( cxscaresult(key, result, package, resulturlmask) )
        elif scanner == 'kics' :
            self.kics.append( cxkicsresult(key, result, resulturlmask) )
