
from urllib import parse


# Helper
class cxbaseresultclass(object) :
    def __init__(self) :
        return
    
    def check_highestseverity( self, currseverity: str, newseverity: str ) :
        curr = currseverity.upper()
        new  = newseverity.upper()
        if curr == new :
            return currseverity
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
            return newseverity
        elif new == 'MEDIUM' and icurr < 2 :
            return newseverity
        elif new == 'HIGH' and icurr < 3 :
            return newseverity
        elif curr == 'CRITICAL'  and icurr < 4 :
            return newseverity
        else :
            return currseverity



class cxsastresultoccourence(object) :
    
    def __init__( self, sastresult, sastresulturlmask: str ) :
        self.id: str                = sastresult['id']
        self.severity: str          = sastresult['severity']
        self.state: str             = sastresult['state']
        self.status: str            = sastresult['status']
        self.similarityid: str      = sastresult['similarityId']
        self.foundat: str           = sastresult['foundAt']
        self.filename: str          = sastresult['data']['nodes'][0]['fileName']
        self.nodes: list            = []
        self.resulthash: str        = sastresult['data']['resultHash']
        self.cxonelink: str         = sastresulturlmask.format(resultid = parse.quote(sastresult['data']['resultHash'], safe = '') ) if sastresult['data']['resultHash'] else None
        # Add the nodes list
        for node in sastresult['data']['nodes'] :
            xnode = { 'name': node['name'], 'filename': node['fileName'], 'line': node['line'], 'column': node['column'] }
            self.nodes.append(xnode)


# One result aggregator
class cxsastresult(cxbaseresultclass) :
    
    def __init__( self, key: str, sastresult, sastresulturlmask: str ) :
        sdescription = ''
        if 'description' in sastresult :
            sdescription = sastresult['description']
        self.key: str               = key
        self.engine: str            = 'sast'
        self.highestseverity: str   = sastresult['severity']
        self.group: str             = sastresult['data']['group'],
        self.queryid: str           = sastresult['data']['queryId'],
        self.queryname: str         = sastresult['data']['queryName']
        self.language: str          = sastresult['data']['languageName'],
        self.cwe: int               = sastresult['vulnerabilityDetails']['cweId']
        self.description: str       = sdescription
        self.occurences: list[cxsastresultoccourence] = []
        self.occurences.append( cxsastresultoccourence(sastresult, sastresulturlmask) )

    def addoccurence( self, sastresult, sastresulturlmask: str ) :
        self.highestseverity = self.check_highestseverity( self.highestseverity, sastresult['severity'])
        self.occurences.append( cxsastresultoccourence(sastresult, sastresulturlmask) )
        
                        

class cxscaresultoccourence(object) :
    
    def __init__( self, scaresult, scaresulturlmask: str ) :
        self.id: str                = scaresult['id']
        self.severity: str          = scaresult['severity']
        self.state: str             = scaresult['state']
        self.status: str            = scaresult['status']
        self.similarityid: str      = scaresult['similarityId']
        self.foundat: str           = scaresult['foundAt']
        self.exploitablepath: int   = len(scaresult['data']['exploitableMethods']) if scaresult['data']['exploitableMethods'] else 0
        self.cxonelink: str         =  scaresulturlmask.format(resultid = parse.quote('/vulnerabilities/' + parse.quote(scaresult['id'] + ':' + scaresult['data']['packageIdentifier'], safe = '') + '/vulnerabilityDetailsGql', safe = ''))
                       
                        
class cxscaresult(cxbaseresultclass) :
    
    def __init__( self, key: str, scaresult, scapackage, scaresulturlmask: str ) :
        sdescription = ''
        if 'description' in scaresult :
            sdescription = scaresult['description']
        self.key: str                   = key
        self.engine: str                = 'sca'
        self.highestseverity: str       = scaresult['severity']
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
        self.occurences: list[cxscaresultoccourence] = []
        self.occurences.append( cxscaresultoccourence(scaresult, scaresulturlmask) )
        
    def addoccurence( self, scaresult, scaresulturlmask: str ) :
        self.highestseverity = self.check_highestseverity( self.highestseverity, scaresult['severity'])
        self.occurences.append( cxscaresultoccourence(scaresult, scaresulturlmask) )



class cxkicsresultoccurence(object) :
    
    def __init__( self, kicsresult, kicsresulturlmask: str ) :
        self.id: str                = kicsresult['ID']
        self.severity: str          = kicsresult['severity'],
        self.state: str             = kicsresult['state']
        self.status: str            = kicsresult['status']
        self.similarityid: str      = kicsresult['similarityID']
        self.foundat: str           = kicsresult['foundAt']
        self.filename: str          = kicsresult['fileName']
        self.line: int              = kicsresult['line']
        self.actualvalue: str       = kicsresult['actualValue']
        self.expectedvalue: str     = kicsresult['expectedValue']
        self.resulthash: str        = kicsresult['ID']
        self.cxonelink: str         = kicsresulturlmask.format(resultid = parse.quote(kicsresult['ID'], safe = '') ) if kicsresult['ID'] else None

                        
class cxkicsresult(cxbaseresultclass) :
    
    def __init__( self, key: str, kicsresult, kicsresulturlmask: str ) :
        sdescription = ''
        if 'description' in kicsresult :
            sdescription = kicsresult['description']
        self.key: str               = key
        self.engine: str            = 'kics'
        self.highestseverity: str   = kicsresult['severity']
        self.group: str             = kicsresult['group']
        self.queryid: str           = kicsresult['queryID']
        self.queryname: str         = kicsresult['queryName']
        self.platform: str          = kicsresult['platform']
        self.issuretype: str        = kicsresult['platform']
        self.category: str          = kicsresult['category']
        self.description: str       = sdescription
        self.occurences: list[cxkicsresultoccurence] = []
        self.occurences.append( cxkicsresultoccurence(kicsresult, kicsresulturlmask) )

    def addoccurence( self, kicsresult, kicsresulturlmask: str ) :
        self.highestseverity = self.check_highestseverity( self.highestseverity, kicsresult['severity'])
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
