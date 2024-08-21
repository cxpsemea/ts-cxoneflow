import os
import sys
if not getattr(sys, 'frozen', False) :
    sys.path.insert(1, os.path.abspath(os.path.dirname(__file__)) + os.sep + '..' + os.sep + 'shared')
from datetime import datetime
from cxloghandler import cxlogger
from baserunner import baserunner
from cxoneconn import cxoneconn
from src.cxconfigdefaults import cxconfigdefaults
from src.cxproperties import cxproperties
from src.cxprocessscan import cxprocessor
from src.cxjirafeedback import jirafeedback
from src.dto.cxcounters import *
from src.dto.cxscan import *


# Accepted bug trackers
BUG_TRACKERS        = ['jira']


class cxoneflow(baserunner) :

    # Overriding
    def printhelp(self) :
        print( '============================================================' )
        print( 'Checkmarx Results Processor' )
        print( '© Checkmarx. All rights reserved.' )
        print( 'Version: ' + self.config.value('version') )
        print( '============================================================' )
        return


    # Overriding
    def execute(self) :
        resultstatus = 0
        errorcount = 0
        # Load configurations           
        self.loadconfig( defaults = cxconfigdefaults, defaultname = 'application' )
        # Init log and verbose
        cxlogger.activate( verbose = True, logging = True, debug = False, logspath = self.config.logsfolder )
        # To compute duration
        dtini = datetime.now()

        try :

            # Verbose the header
            cxlogger.verbose( '' )
            cxlogger.verbose( '============================================================' )
            cxlogger.verbose( 'Checkmarx Results Processor' )
            cxlogger.verbose( '© Checkmarx. All rights reserved.' )
            cxlogger.verbose( 'Version: ' + self.config.value('version') )
            cxlogger.verbose( '============================================================' )
            cxlogger.verbose( 'Date: ' + dtini.strftime('%d-%m-%Y %H:%M:%S') )
            
            # Load configurations
            cxlogger.verbose( 'Processing parameters')
            cxparams = cxproperties( self.config )

            # Check for scan id mandatory input param
            if not cxparams.scanid :
                raise Exception( 'Scan id was not supplyed')
            cxlogger.verbose( 'Scan id: ' + cxparams.scanid )

            # Check aditional input params
            paramsok        = False
            # From params, Namespace/Repo/Branch provided
            if cxparams.namespace and cxparams.repository and cxparams.branch :
                paramsok        = True
                cxlogger.verbose( 'Arguments: namespace - ' + cxparams.namespace + ', repository - ' + cxparams.repository + ', branch - ' + cxparams.branch )
            # From params, only application and repo provided
            elif cxparams.application and cxparams.repository  :
                paramsok        = True
                cxlogger.verbose( 'Arguments: app -  ' + cxparams.application + ', repository - ' + cxparams.repository )
            # From params, only application
            elif cxparams.application :
                paramsok        = True
                cxlogger.verbose( 'Arguments: app - ' + cxparams.application )
            if not paramsok :
                raise Exception( 'Namespace/Repo/Branch or App must be provided in order to properly track')

            if not cxparams.bug_tracker  :
                raise Exception( 'No bug tracker selected')
            if not cxparams.bug_tracker in BUG_TRACKERS :
                raise Exception( 'Bug tracker "' + cxparams.bug_tracker + '" is not compatible')
            cxlogger.verbose( 'Bug tracker: ' + cxparams.bug_tracker )

            cxlogger.verbose( '============================================================' )

            # Connect to CXONE instance
            cxxoneconn = None
            try :
                cxlogger.verbose( 'Connecting to CXONE "' + self.config.value('cxone.url') + '"' )
                # Check required parameters
                cxone_url       = self.config.value('cxone.url')
                cxone_acl       = self.config.value('cxone.acl')
                cxone_tenant    = self.config.value('cxone.tenant')
                cxone_apikey    = self.config.value('cxone.apikey')
                cxone_clientid  = self.config.value('cxone.clientid')
                cxone_granttype = self.config.value('cxone.granttype')
                if not cxone_url :
                    raise Exception( 'Missing CxOne url' )
                if not cxone_tenant :
                    raise Exception( 'Missing CxOne tenant name' )
                if not cxone_apikey:
                    raise Exception( 'Missing CxOne api key/client secret' )
                if not cxone_clientid and (cxone_granttype == 'client_credentials') :
                    raise Exception( 'Missing CxOne client id' )
                cxxoneconn = cxoneconn( cxone_url, cxone_tenant, cxone_apikey, cxone_acl, cxone_clientid, cxone_granttype, 
                                self.config.value('cxone.proxy_url'), self.config.value('cxone.proxy_username'), self.config.value('cxone.proxy_password') )
                cxxoneconn.logon()
                ver = cxxoneconn.versionstring
                if not ver or ver == '0' :
                    raise Exception( 'Cound not obtain cxone version' )
                cxlogger.verbose( 'Connected to CXONE, version ' + ver )
            except Exception as e:
                errorcount += 1
                raise Exception( 'Failed connecting to CXONE with "' + str(e) + '"', True, True, e )
            # Check if THIS user has the required permissions
            cxxoneconn.checkpermissions( perm_cxone = True, perm_accesscontrol = False, perm_dast = False, perm_cxreportonly = True )

            has_results = False
            scandata    = None
            counters    = None
            results     = None

            # Process scan results
            runner = cxprocessor( self.config, cxxoneconn, cxparams )
            has_results = runner.processscan()

            if has_results :
                feeder      = None
                scandata    = runner.scan
                counters    = runner.counters
                results     = runner.results

                if (len(results.sast) > 0) or (len(results.sca) > 0) or (len(results.kics) > 0 ) :
                    # Create tickets ?
                    if cxparams.bug_tracker == 'jira' :
                        feeder = jirafeedback( self.config, cxparams, scandata, results )
                    if feeder :
                        cxlogger.verbose( '============================================================' )
                        feeder.processfeedback()
                    else :
                        cxlogger.verbose( 'SKIPPED: no supported bug-tracker found' )
                    
                    # Check thresholds/break build ?
                    break_build = False
                    if feeder and cxparams.has_thresholds() :
                        
                        # Evaluate SAST
                        if cxparams.sast_threshold_new and counters.sast.new >= cxparams.sast_threshold_new :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST New ' + str(counters.sast.new) + ' reached ' + str(cxparams.sast_threshold_new ) + ' limit!' )
                        if cxparams.sast_threshold_critical and counters.sast.critical >= cxparams.sast_threshold_critical :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST Critical ' + str(counters.sast.critical) + ' reached ' + str(cxparams.sast_threshold_critical ) + ' limit!' )
                        if cxparams.sast_threshold_high and counters.sast.high >= cxparams.sast_threshold_high :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST High ' + str(counters.sast.high) + ' reached ' + str(cxparams.sast_threshold_high ) + ' limit!' )
                        if cxparams.sast_threshold_medium and counters.sast.medium >= cxparams.sast_threshold_medium :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST Medium ' + str(counters.sast.medium) + ' reached ' + str(cxparams.sast_threshold_medium ) + ' limit!' )
                        if cxparams.sast_threshold_low and counters.sast.low >= cxparams.sast_threshold_low :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST Low ' + str(counters.sast.low) + ' reached ' + str(cxparams.sast_threshold_low ) + ' limit!' )
                    
                        # Evaluate SCA
                        if cxparams.sca_threshold_new and counters.sca.new >= cxparams.sca_threshold_new :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA New ' + str(counters.sca.new) + ' reached ' + str(cxparams.sca_threshold_new ) + ' limit!' )
                        if cxparams.sca_threshold_critical and counters.sca.critical >= cxparams.sca_threshold_critical :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA Critical ' + str(counters.sca.critical) + ' reached ' + str(cxparams.sca_threshold_critical ) + ' limit!' )
                        if cxparams.sca_threshold_high and counters.sca.high >= cxparams.sca_threshold_high :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA High ' + str(counters.sca.high) + ' reached ' + str(cxparams.sca_threshold_high ) + ' limit!' )
                        if cxparams.sca_threshold_medium and counters.sca.medium >= cxparams.sca_threshold_medium :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA Medium ' + str(counters.sca.medium) + ' reached ' + str(cxparams.sca_threshold_medium ) + ' limit!' )
                        if cxparams.sca_threshold_low and counters.sca.low >= cxparams.sca_threshold_low :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA Low ' + str(counters.sca.low) + ' reached ' + str(cxparams.sca_threshold_low ) + ' limit!' )
                        if cxparams.sca_threshold_score and counters.sca.cvsscore >= cxparams.sca_threshold_score :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA Highest CVSS Score ' + str(counters.sca.cvsscore) + ' reached ' + str(cxparams.sca_threshold_score ) + ' limit, package "' + counters['sca']['CvsScorePackage'] + '"!' )
                            
                        # Evaluate KICS
                        if cxparams.kics_threshold_new and counters.kics.new >= cxparams.kics_threshold_new :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS New ' + str(counters.kics.new) + ' reached ' + str(cxparams.kics_threshold_new ) + ' limit!' )
                        if cxparams.kics_threshold_critical and counters.kics.critical >= cxparams.kics_threshold_critical :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS Critical ' + str(counters.kics.critical) + ' reached ' + str(cxparams.kics_threshold_critical ) + ' limit!' )
                        if cxparams.kics_threshold_high and counters.kics.high >= cxparams.kics_threshold_high :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS High ' + str(counters.kics.high) + ' reached ' + str(cxparams.kics_threshold_high ) + ' limit!' )
                        if cxparams.kics_threshold_medium and counters.kics.medium >= cxparams.kics_threshold_medium :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS Medium ' + str(counters.kics.medium) + ' reached ' + str(cxparams.kics_threshold_medium ) + ' limit!' )
                        if cxparams.kics_threshold_low and counters.kics.low >= cxparams.kics_threshold_low :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS Low ' + str(counters.kics.low) + ' reached ' + str(cxparams.kics_threshold_low ) + ' limit!' )
                            
                    if break_build :
                        if cxparams.break_build :
                            resultstatus = 10
                            cxlogger.verbose( 'THRESHOLD VIOLATION, breaking build with exit code 10.' )
                        else: 
                            cxlogger.verbose( 'THRESHOLD VIOLATION, breaking build is disabled!' )

                else :
                    cxlogger.verbose( 'SKIPPED: no elegible results found to process' )
            else :
                cxlogger.verbose( 'SKIPPED: no elegible results found to process' )

        except Exception as e:
            cxlogger.verbose( str(e), True, False, True, e )
            resultstatus = 9
        finally :
            # Verbose the footer
            dtend = datetime.now()
            cxlogger.verbose( '============================================================' )
            cxlogger.verbose( 'Ended: ' + dtend.strftime('%d-%m-%Y %H:%M:%S') )
            cxlogger.verbose( 'Total duration: ' + self.duration(dtini, False) )
            if errorcount > 0 :
                cxlogger.verbose( str(errorcount) + ' errors were found.' )    
            cxlogger.verbose( '============================================================' )
            cxlogger.verbose( '' )
        return resultstatus



if __name__ == '__main__' :
    application = cxoneflow()
    status = application.execute()
    sys.exit(status)
