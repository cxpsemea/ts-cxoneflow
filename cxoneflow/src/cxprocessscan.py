
import time
from datetime import datetime
from urllib import parse
from cxloghandler import cxlogger
from config import config
from baserunner import baserunner
from cxoneconn import cxoneconn
from .cxproperties import cxproperties
from .dto.cxcounters import *
from .dto.cxscan import *
from .dto.cxresults import *



class cxprocessor(baserunner) :

    def __init__(self, config: config, conn: cxoneconn, cxparams: cxproperties ) :
        # Sca packages list (internal use)
        self.__sca_packages         = []
        # Scan info
        self.__scan                 = cxscan()
        # Counters
        self.__counters             = cxresultscounters()
        # Results aggregated
        self.__results              = cxresults()
        # Params
        self.cxparams               = cxparams
        super().__init__(config, conn, None, None, None)


    @property
    def scan(self) :
        return self.__scan


    @property
    def counters(self) :
        return self.__counters


    @property
    def results(self) :
        return self.__results


    # Get scan information, wait for completion
    def __getscandata(self, scanid: str, waitforit: bool = True ) :
        # Get scan and status. Error is thrown if scan does not exists
        scan = self.conn.cxone.get( '/api/scans/' + scanid )
        while scan['status'] != 'Completed' and waitforit :
            # 30 seconds
            time.sleep(30.0)
            scan = self.conn.cxone.get( '/api/scans/' + scanid )
        # Get associated project data
        project = self.conn.cxone.get( '/api/projects/' + scan['projectId'] )
        self.__scan.updatescandata( scan, project )
    
    
    # Check branch name and scanners for processing go/no-go
    def __checkscandata( self ) :
        go = True
        # Check branch
        if self.cxparams.filter_branches :
            scanbranch = self.__scan.branch
            go = scanbranch and scanbranch.lower() in self.cxparams.filter_branches
            if not go :
                if scanbranch :
                    cxlogger.verbose( 'ABORTED: branch "' + scanbranch + '" not matching any observed branches ' + str(self.cxparams.filter_branches) )
                else :
                    cxlogger.verbose( 'ABORTED: no branch detected to match observed branches ' + str(self.cxparams.filter_branches) )
        # Check scanners
        if self.cxparams.filter_scanners :
            found = 0
            statuses = self.__scan.statusdetails
            for status in statuses :
                if status['name'].lower() in self.cxparams.filter_scanners :
                    found += 1
            go = found > 0
            if not go :
                cxlogger.verbose( 'ABORTED: scan not matching any observed scanners ' + str(self.cxparams.filter_scanners) )
        # Ret
        return go


    def __processscanresults( self, scanresults, thescanner ) :

        sastresulturlmask   = self.cxparams.cxurl + '/results/' + self.__scan.id + '/' + self.__scan.projectid + '/sast?result-id={resultid}'
        scaresulturlmask    = self.cxparams.cxurl + '/results/' + self.__scan.projectid + '/' + self.__scan.id + '/sca?internalPath={resultid}'
        kicsresulturlmask   = self.cxparams.cxurl + '/results/' + self.__scan.id + '/' + self.__scan.projectid + '/kics?result-id={resultid}'
        
        for result in scanresults :
            
            if not thescanner :
                scanner = result['type']
                # Kics results arrive separatedlly
                if scanner == 'kics' :
                    scanner = 'none' 
            else :
                scanner = thescanner
            
            elegible = scanner in self.cxparams.filter_scanners
            
            if scanner == 'sast' and elegible :
                # Auto-exclude not exploitables unless explicitly selected
                if not ( self.cxparams.sast_filter_state and ('not_exploitable' in self.cxparams.sast_filter_state) ) :
                    if str(result['state']).lower() == 'not_exploitable' :
                        elegible = False
                # Check severity
                if elegible and ( self.cxparams.sast_filter_severities and str(result['severity']).lower() not in self.cxparams.sast_filter_severities ) :
                    elegible = False
                # Check state
                if elegible and ( self.cxparams.sast_filter_state and str(result['state']).lower() not in self.cxparams.sast_filter_state ) :
                    elegible = False
                # Check categories (query names)
                if elegible and ( self.cxparams.sast_filter_categories and str(result['data']['queryName']).lower() not in self.cxparams.sast_filter_categories ) :
                    elegible = False
                # Check CWE 
                if elegible and ( self.cxparams.sast_filter_cwes and str(result['vulnerabilityDetails']['cweId']).lower() not in self.cxparams.sast_filter_cwes ) :
                    elegible = False
                
                # If elegible, aggregate it
                if elegible :
                    # Increment counters
                    self.__counters.getcounter(scanner).updatecount(result)
                    # SAST result key compatible with CxOne feedback apps and with legacy CxFlow
                    key = str(result['data']['queryName']) + ' @ ' + str(result['data']['nodes'][0]['fileName'])
                    # Process it
                    cxresult = self.__results.findresult( scanner, key )
                    if cxresult :
                        cxresult.addoccurence( result, sastresulturlmask )
                    else :
                        self.__results.addresult( scanner, key, result, sastresulturlmask )
                    
            elif scanner == 'sca' and elegible :
                # Auto-exclude not exploitables unless explicitly selected
                if not ( self.cxparams.sca_filter_state and ('not_exploitable' in self.cxparams.sca_filter_state) ) :
                    if str(result['state']).lower() == 'not_exploitable' :
                        elegible = False
                # Check severity
                if elegible and ( self.cxparams.sca_filter_severities and str(result['severity']).lower() not in self.cxparams.sca_filter_severities ) :
                    elegible = False
                # Check state
                if elegible and ( self.cxparams.sca_filter_state and str(result['state']).lower() not in self.cxparams.sca_filter_state ) :
                    elegible = False
                # Check CVS score (sca only)
                if elegible and self.cxparams.sca_filter_cvsscore  :
                    score = result['vulnerabilityDetails']['cvssScore']
                    if score < self.cxparams.sca_filter_cvsscore :
                        elegible = False
                # Retrieve package data
                if elegible :
                    package = next( filter( lambda el: el['packageId'] == result['data']['packageIdentifier'], self.__sca_packages ), None )
                    if package :
                        # Check filter package type
                        if self.cxparams.sca_filter_ignore_dev_test and ( package['isDev'] or package['isTest'] ) :
                            elegible = False
                        # Check filter policy violation
                        if elegible and self.cxparams.sca_filter_policyviolation :
                            elegible = package['isViolatingPolicy']
                    else :
                        elegible = False
                # Retrieve exploitable path data
                if elegible and self.cxparams.sca_filter_exploitablepath :
                    if result['data']['exploitableMethods'] and len(result['data']['exploitableMethods']) > 0 :
                        elegible = True
                    else :
                        elegible = False
                        
                # If elegible, aggregate it
                if elegible :
                    # Increment counters
                    self.__counters.getcounter(scanner).updatecount(result)
                    # SCA result key compatible with CxOne feedback apps
                    key = str(result['id']) + ' ' + str(result['data']['packageIdentifier'])
                    # Process it
                    cxresult = self.__results.findresult( scanner, key )
                    if not cxresult :
                        self.__results.addresult( scanner, key, result, scaresulturlmask, package )
            
            elif scanner == 'kics' and elegible :
                # Auto-exclude not exploitables unless explicitly selected
                if not ( self.cxparams.kics_filter_state and ('not_exploitable' in self.cxparams.kics_filter_state) ) :
                    if str(result['state']).lower() == 'not_exploitable' :
                        elegible = False
                # Check severity
                if elegible and ( self.cxparams.kics_filter_severities and str(result['severity']).lower() not in self.cxparams.kics_filter_severities ) :
                    elegible = False
                # Check state
                if elegible and ( self.cxparams.kics_filter_state and str(result['state']).lower() not in self.cxparams.kics_filter_state ) :
                    elegible = False
                # Check categories (query names)
                if elegible and ( self.cxparams.kics_filter_categories and str(result['queryName']).lower() not in self.cxparams.kics_filter_categories ) :
                    elegible = False
                    
                # If elegible, aggregate it
                if elegible :
                    # Increment counters
                    self.__counters.getcounter(scanner).updatecount(result)
                    # KICS result key compatible with CxOne feedback apps
                    key = str(result['queryName']) + ' @ ' + str(result['fileName'])
                    # Process it
                    cxresult = self.__results.findresult( scanner, key )
                    if cxresult :
                        cxresult.addoccurence( result, kicsresulturlmask )
                    else :
                        self.__results.addresult( scanner, key, result, kicsresulturlmask )
                
        return

    
    def __process_sca_packages(self) :
        cxlogger.verbose( 'Processing sca libraries' )
        skip        = 0
        limit       = 100
        counter     = 0
        # If we have a dependency type filter, then apply it
        dependencies = '{"eq":"Direct"},{"eq":"Transitive"},{"eq":"Mixed"}'
        if self.cxparams.sca_filter_dependency_type :
            if self.cxparams.sca_filter_dependency_type == 'direct' :
                dependencies = '{"eq":"Direct"},{"eq":"Mixed"}'
            elif self.cxparams.sca_filter_dependency_type == 'transitive' :
                dependencies = '{"eq":"Transitive"},{"eq":"Mixed"}'
        # Prepare graphql query
        tql: str = '{"query":"query ($where: PackageRowModelFilterInput, $take: Int!, $skip: Int!, $order: [PackagesSort!], $isExploitablePathEnabled: Boolean!, $scanId: UUID!) '
        tql = tql + '{ packagesRows (where: $where, take: $take, skip: $skip, order: $order, isExploitablePathEnabled: $isExploitablePathEnabled, scanId: $scanId) ' 
        tql = tql + '{ items { packageId, name, version, isViolatingPolicy, isMalicious, dependencyPathCount, violatedPoliciesCount, violatedPolicies, relation, matchType, legalRiskLevel, '
        tql = tql + 'isDev, isTest, isNpmVerified, isPluginDependency, packageRepository, packageUsage, releaseDate, isPrivateDependency, outdatedModel '
        tql = tql + '{ newestVersion, versionsInBetween, newestLibraryDate }, saasProviderInfo { name, key, type }, '
        tql = tql + 'licenses { packageId, packageName, packageVersion, name, riskLevel, copyrightRiskLevel, copyLeftType, patentRiskLevel, licenseUrl, referenceType, reference, isViolatingPolicy }, '
        tql = tql + 'risks { vulnerabilities { critical, high, medium, low }, '
        tql = tql + 'legalRisk { critical, high, medium, low }, '
        tql = tql + 'supplyChainRisks { critical, high, medium, low }, '
        tql = tql + 'vulnerabilitiesWithoutIgnored { critical, high, medium, low }, '
        tql = tql + 'supplyChainRisksWithoutIgnored { critical, high, medium, low } } }, totalCount } }", '
        tql = tql + '"variables":{"where":{"and":{"relation":{"or":[' + dependencies + ']},'
        tql = tql + '"isPrivateDependency":{"neq":true},"isSaasProvider":{"eq":false}}}, '
        tql = tql + '"order":{"risks":"DESC"},"isExploitablePathEnabled":false,"scanId":"' + self.cxparams.scanid + '",'
        # The pagination
        graphql = tql + '"take":' + str(limit) + ',"skip":' + str(skip) + '} }'
        # Go for it
        data = self.conn.cxone.post( '/api/sca/graphql/graphql', body = graphql )
        while ( data and data['data'] and data['data']['packagesRows'] and data['data']['packagesRows']['items'] and len( data['data']['packagesRows']['items'] ) > 0 ) :
            counter += len(data['data']['packagesRows']['items'])
            cxlogger.verbose( '- Processing ' + str(counter) + ' sca libraries' )
            self.__sca_packages.extend( data['data']['packagesRows']['items'] )
            skip += limit
            graphql = tql + '"take":' + str(limit) + ',"skip":' + str(skip) + '} }'
            data = self.conn.cxone.post( '/api/sca/graphql/graphql', body = graphql )
    


    def processscan(self) :
        
        self.__getscandata( self.cxparams.scanid )

        go = self.__checkscandata()
        
        if go :
            
            # Get sca package information for package references
            if 'sca' in self.cxparams.filter_scanners :
                self.__process_sca_packages()
                
            # Get sast/sca scan results (use all scan results api to obtain description)
            if ('sast' in self.cxparams.filter_scanners) or ('sca' in self.cxparams.filter_scanners) :
                cxlogger.verbose( 'Processing scan results' )
                page        = 0
                limit       = 100
                counter     = 0
                data = self.conn.cxone.get( '/api/results?offset=' + str(page) + '&limit=' + str(limit) + '&scan-id=' + self.cxparams.scanid )
                while data and data['results'] and len(data['results']) > 0 :
                    counter += len( data['results'] )
                    cxlogger.verbose( '- Processing ' + str(counter) + ' results' )
                    # Aggregate results
                    self.__processscanresults( data['results'], None )
                    # Next page
                    page += 1
                    data = self.conn.cxone.get( '/api/results?offset=' + str(page) + '&limit=' + str(limit) + '&scan-id=' + self.cxparams.scanid )

            
            # Get kics scan results (required to obtain the result IDs for links)
            if 'kics' in self.cxparams.filter_scanners :
                cxlogger.verbose( 'Processing kics scan results' )
                page        = 0
                limit       = 100
                counter     = 0
                data = self.conn.cxone.get( '/api/kics-results?scan-id=' + self.cxparams.scanid + '&offset=' + str(page) + '&limit=' + str(limit) )
                while data and data['results'] and len(data['results']) > 0 :
                    counter += len( data['results'] )
                    cxlogger.verbose( '- Processing ' + str(counter) + ' kics results' )
                    # Aggregate results
                    self.__processscanresults( data['results'], 'kics' )
                    # Next page
                    page += limit
                    data = self.conn.cxone.get( '/api/kics-results?scan-id=' + self.cxparams.scanid + '&offset=' + str(page) + '&limit=' + str(limit) )
            
        # Return data yes/no
        return go





