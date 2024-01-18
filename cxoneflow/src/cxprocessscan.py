
import time
from datetime import datetime
from urllib import parse
from cxloghandler import cxlogger
from config import config
from baserunner import baserunner
from cxoneconn import cxoneconn
from .cxproperties import cxproperties



class cxprocessor(baserunner) :

    def __init__(self, config: config, conn: cxoneconn, cxparams: cxproperties ) :
        # Scan info
        self.__scan                 = None  
        # Counters
        self.__counters             = {}
        # Results aggregated
        self.__aggergators          = {}
        # Sca packages list
        self.__sca_packages         = []
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
        return self.__aggergators


    # Get scan information, wait for completion
    def __getscandata(self, scanid: str, waitforit: bool = True ) :
        # Get scan and status. Error is thrown if scan does not exists
        # Scan already includes a scan "tags" element
        scan = self.conn.cxone.get( '/api/scans/' + scanid )
        while scan['status'] != 'Completed' and waitforit :
            # 30 seconds
            time.sleep(30.0)
            scan = self.conn.cxone.get( '/api/scans/' + scanid )
        # Process scan tags
        scantagstext = ''
        scantags = scan['tags']
        scan['scan-tags'] = []
        tagkeys = list(scantags.keys())
        if tagkeys and len(tagkeys) > 0 :
            tagname = tagkeys[0]
            tagvalue = scantags[tagkeys[0]]
            if not tagvalue :
                tagvalue = tagname
            scan['scan-tags'].append( { 'name': tagname, 'value': tagvalue } )
            if scantagstext :
                scantagstext = scantagstext + ', '
            scantagstext = scantagstext + tagname + ': ' + tagvalue
        scan['scan-tags-text'] = scantagstext
        # Process project tags
        project = self.conn.cxone.get( '/api/projects/' + scan['projectId'] )
        projecttagstext = ''
        projecttags = project['tags']
        scan['project-tags'] = []
        tagkeys = list(projecttags.keys())
        if tagkeys and len(tagkeys) > 0 :
            tagname = tagkeys[0]
            tagvalue = projecttags[tagkeys[0]]
            if not tagvalue :
                tagvalue = tagname
            scan['project-tags'].append( { 'name': tagname, 'value': tagvalue } )
            if projecttagstext :
                projecttagstext = scantagstext + ', '
            projecttagstext = scantagstext + tagname + ': ' + tagvalue
        scan['project-tags-text'] = scantagstext
        return scan
    
    
    # Check branch name and scanners for processing go/no-go
    def __checkscandata( self, scandata ) :
        go = True
        # Check branch
        if self.cxparams.filter_branches :
            scanbranch = scandata['branch']
            go = scanbranch and scanbranch.lower() in self.fcxparams.filter_branches
            if not go :
                if scanbranch :
                    cxlogger.verbose( 'ABORTED: branch "' + scanbranch + '" not matching any observed branches ' + str(self.cxparams.filter_branches) )
                else :
                    cxlogger.verbose( 'ABORTED: no branch detected to match observed branches ' + str(self.cxparams.filter_branches) )
        # Check scanners
        if self.cxparams.filter_scanners :
            found = 0
            statuses = scandata['statusDetails']
            for status in statuses :
                if status['name'].lower() in self.cxparams.filter_scanners :
                    found += 1
            go = found > 0
            if not go :
                cxlogger.verbose( 'ABORTED: scan not matching any observed scanners ' + str(self.cxparams.filter_scanners) )
        # Ret
        return go


    def __highestseverity( self, currseverity: str, newseverity: str ) :
        curr = currseverity.upper()
        new  = newseverity.upper()
        icurr: int = 0
        inew: int = 0
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


    def __processscanresults( self, scanresults ) :

        resultsurl = self.cxparams.cxurl + '/results/' + self.__scan['projectId'] + '/' + self.__scan['id']

        for result in scanresults :
            scanner     = result['type']
            elegible    = scanner in self.cxparams.filter_scanners
            package     = None

            # Check filters according to scanner
            if elegible and scanner == 'sast' :
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
                if elegible and ( self.cxparams.sast_filter_cwes and str(result['vulnerabilityDetails']['cweID']).lower() not in self.cxparams.sast_filter_cwes ) :
                    elegible = False
            elif elegible and scanner == 'kics' :
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
                if elegible and ( self.cxparams.kics_filter_categories and str(result['data']['queryName']).lower() not in self.cxparams.kics_filter_categories ) :
                    elegible = False
            elif elegible and scanner == 'sca' :
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
            else :
                elegible = False


            if elegible :

                # Update counters
                counters = self.__counters[scanner]
                if str(result['status']).lower() == 'new' :
                    counters['New'] += 1
                else :
                    counters['Recurrent'] += 1
                if str(result['severity']).lower() == 'critical' :
                    counters['Critical'] += 1
                elif str(result['severity']).lower() == 'high' :
                    counters['High'] += 1
                elif str(result['severity']).lower() == 'medium' :
                    counters['Medium'] += 1
                elif str(result['severity']).lower() == 'low' :
                    counters['Low'] += 1
                elif str(result['severity']).lower() == 'info' :
                    counters['Info'] += 1

                if scanner == 'sca' :
                    score =  result['vulnerabilityDetails']['cvssScore']
                    if score > counters['CvsScore'] :
                        counters['CvsScore']        = score
                        counters['CvsScorePackage'] = result['data']['packageIdentifier']

                # Aggergate
                if self.__aggergators[scanner] == None :
                    self.__aggergators[scanner] = []
                if scanner == 'sast' :
                    ref = str(result['data']['languageName']) + ' ' + str(result['data']['queryName']) + ' ' + str(result['data']['nodes'][0]['fileName'])
                    agg = next( filter( lambda el: el['key'] == ref, self.__aggergators[scanner] ), None )
                    if not agg :
                        agg = { 'key': ref,
                                'engine': scanner,
                                'confidencelevel': result['confidenceLevel'],
                                'firstfoundat': result['firstFoundAt'],
                                'firstscanid': result['firstScanId'],
                                'foundat': result['foundAt'],
                                # 'cvss': result['cvssScore'],
                                'cwe': result['vulnerabilityDetails']['cweId'],
                                'language': result['data']['languageName'],
                                'group': result['data']['group'],
                                'queryid': result['data']['queryId'],
                                'queryname': result['data']['queryName'],
                                'state': result['state'],
                                'status': result['status'],
                                'severity': result['severity'],
                                'similarityid': result['similarityId'],
                                'description': result['description'],
                                'filename': str(result['data']['nodes'][0]['fileName']).lstrip('/').lstrip('\\'),
                                'resulthash': result['data']['resultHash'], 
                                'cxonelink': resultsurl + '/sast?result-id=' + parse.quote(result['data']['resultHash'], safe = '') + '&redirect=false' if result['data']['resultHash'] else None,
                                'comment': None,
                                'results': []
                            }
                        self.__aggergators[scanner].append( agg )
                    elif len(agg['results']) > 0 :
                        agg['severity'] = self.__highestseverity( agg['severity'], result['severity'] ) 
                    res = { 'line': result['data']['nodes'][0]['line'],
                            'column': result['data']['nodes'][0]['column'], 
                            'domtype': result['data']['nodes'][0]['domType'], 
                            'methodline': result['data']['nodes'][0]['methodLine'], 
                            'resulthash': result['data']['resultHash'],
                            'similarityid': result['similarityId'],
                            'state': result['state'],
                            'severity': result['severity'],
                            'cxonelink': resultsurl + '/sast?result-id=' + parse.quote(result['data']['resultHash'], safe = '') + '&redirect=false' if result['data']['resultHash'] else None
                            }
                    agg['results'].append(res)
                elif scanner == 'kics' :
                    ref = str(result['data']['platform']) + ' ' + str(result['data']['queryName']) + ' ' + str(result['data']['fileName'])
                    agg = next( filter( lambda el: el['key'] == ref, self.__aggergators[scanner] ), None )
                    if not agg :
                        agg = { 'key': ref,
                                'engine': scanner,
                                'confidencelevel': result['confidenceLevel'],
                                'firstfoundat': result['firstFoundAt'],
                                'firstscanid': result['firstScanId'],
                                'foundat': result['foundAt'],
                                # 'cvss': result['cvssScore'],
                                'cwe': None,
                                'platform': result['data']['platform'],
                                'group': str(result['data']['group']).replace( '[Taken from category]', '' ).strip(),
                                'queryid': str(result['data']['queryId']).replace( '[Taken from category]', '' ).strip(),
                                'queryname': result['data']['queryName'],
                                'state': result['state'],
                                'status': result['status'],
                                'severity': result['severity'],
                                'similarityid': result['similarityId'],
                                'description': result['description'],
                                'filename': str(result['data']['fileName']).lstrip('/').lstrip('\\'),
                                'issuetype': result['data']['issueType'],
                                'value': result['data']['value'],
                                'expectedvalue': result['data']['expectedValue'],
                                'cxonelink': None,
                                'comment': None,
                                'results': []
                            }
                        self.__aggergators[scanner].append( agg )
                    elif len(agg['results']) > 0 :
                        agg['severity'] = self.__highestseverity( agg['severity'], result['severity'] ) 
                    res = { 'line': result['data']['line'],
                            'issuetype': result['data']['issueType'],
                            'value': result['data']['value'],
                            'expectedvalue': result['data']['expectedValue'],
                            'similarityid': result['similarityId'],
                            'state': result['state'],
                            'severity': result['severity'],
                            'cxonelink': None
                            }
                    agg['results'].append(res)
                elif scanner == 'sca' :
                    ref = str(result['id']) + ' ' + str(result['data']['packageIdentifier'])
                    agg = next( filter( lambda el: el['key'] == ref, self.__aggergators[scanner] ), None )
                    if not agg :
                        agg = { 'key': ref,
                                'engine': scanner,
                                'id': result['id'],
                                'confidencelevel': result['confidenceLevel'],
                                'firstfoundat': result['firstFoundAt'],
                                'firstscanid': result['firstScanId'],
                                'foundat': result['foundAt'],
                                'cvss': result['vulnerabilityDetails']['cvssScore'],
                                'cve': result['vulnerabilityDetails']['cveName'],
                                'cwe': result['vulnerabilityDetails']['cweId'],
                                'packageid': result['data']['packageIdentifier'],
                                'recommendedversion': result['data']['recommendedVersion'],
                                'packagedata': result['data']['packageData'],
                                # >> From package
                                'packagename': package['name'],
                                'packageversion': package['version'],
                                'packagerepository': package['packageRepository'],
                                'relation': package['relation'],
                                'isdev': package['isDev'],
                                'istest': package['isTest'],
                                'matchtype': package['matchType'],
                                'releasedate': package['releaseDate'],
                                'legalrisklevel': package['legalRiskLevel'],
                                'dependencypathcount': package['dependencyPathCount'],
                                'newestversion': package['outdatedModel']['newestVersion'],
                                'newestdate': package['outdatedModel']['newestLibraryDate'],
                                'versionsbetween': package['outdatedModel']['versionsInBetween'],
                                'violatedpoliciescount': package['violatedPoliciesCount'],
                                'violatedpolicies': package['violatedPolicies'],
                                # << From package
                                'state': result['state'],
                                'status': result['status'],
                                'severity': result['severity'],
                                'similarityid': result['similarityId'],
                                'description': result['description'],
                                'cxonelink': resultsurl + '/sca?internalPath=' + parse.quote('/vulnerabilities/' + parse.quote(result['id'] + ':' + result['data']['packageIdentifier'], safe = '') + '/vulnerabilityDetailsGql', safe = ''), 
                                'comment': None,
                                'results': []
                            }
                        self.__aggergators[scanner].append( agg )
                    elif len(agg['results']) > 0 :
                        agg['severity'] = self.__highestseverity( agg['severity'], result['severity'] ) 
                    res = { 'id': result['id'],
                            'relation': package['relation'],
                            'isdev': package['isDev'],
                            'istest': package['isTest'],
                            'matchtype': package['matchType'],
                            'similarityid': result['similarityId'],
                            'state': result['state'],
                            'severity': result['severity'],
                            'cxonelink': resultsurl + '/sca?internalPath=' + parse.quote('/vulnerabilities/' + parse.quote(result['id'] + ':' + result['data']['packageIdentifier'], safe = '') + '/vulnerabilityDetailsGql', safe = '')
                            }
                    agg['results'].append(res)




    def processscan(self) :

        self.__scan = self.__getscandata( self.cxparams.scanid )

        go = self.__checkscandata(self.__scan)

        if go :


            # Init counters
            counterrec = { 'New': 0, 'Recurrent': 0, 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'CvsScore': 0, 'CvsScorePackage': None }
            self.__counters['sast']             = counterrec
            self.__counters['sca']              = counterrec
            self.__counters['kics']             = counterrec

            # Init aggregators
            self.__aggergators['sast']          = None
            self.__aggergators['sca']           = None
            self.__aggergators['kics']          = None

            # Get packages details if sca scanner is used
            if ('sca' in self.cxparams.filter_scanners)  :

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

            cxlogger.verbose( 'Processing scan results' )


            # Collect scan results (all scanners)
            page        = 0
            limit       = 100
            scanresults = []
            counter     = 0
            data = self.conn.cxone.get( '/api/results?offset=' + str(page) + '&limit=' + str(limit) + '&scan-id=' + self.cxparams.scanid )
            if data :
                scanresults = data['results']
            else :
                cxlogger.verbose( 'No results found in scan to process' )
            while len(scanresults) > 0 :
                counter += len(scanresults)
                cxlogger.verbose( '- Processing ' + str(counter) + ' results' )
                # Aggregate results
                self.__processscanresults( scanresults )
                # Next page
                page += 1
                scanresults = []
                data = self.conn.cxone.get( '/api/results?offset=' + str(page) + '&limit=' + str(limit) + '&scan-id=' + self.cxparams.scanid )
                if data :
                    scanresults = data['results']

        # Return data yes/no
        return go



