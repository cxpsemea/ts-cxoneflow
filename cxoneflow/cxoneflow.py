import os
import sys
if not getattr(sys, 'frozen', False) :
    sys.path.insert(1, os.path.abspath(os.path.dirname(__file__)) + os.sep + '..' + os.sep + 'shared')
from datetime import datetime
from cxloghandler import cxlogger
from baserunner import baserunner
from cxoneconn import cxoneconn
from src.cxproperties import cxproperties
from src.cxprocessscan import cxprocessor
from src.cxjirafeedback import jirafeedback


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
        self.loadconfig( defaultname = 'application' )
        # Load configurations
        cxparams = cxproperties( self.config )
        # Init log and verbose
        # cxlogger.activate( verbose = self.verbose, logging = True, debug = False )
        cxlogger.activate( verbose = True, logging = True, debug = False )
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
                cxxoneconn = cxoneconn( self.config.value('cxone.url'), self.config.value('cxone.tenant'), self.config.value('cxone.apikey'), 
                                self.config.value('cxone.acl'), self.config.value('cxone.clientid'), self.config.value('cxone.granttype'), 
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

                if results['sast'] or results['sca'] or results['kics'] :
                    # Create tickets ?
                    if cxparams.bug_tracker == 'jira' :
                        feeder = jirafeedback( self.config, cxparams, scandata, results )
                    if feeder :
                        feeder.processfeedback()
                    else :
                        cxlogger.verbose( 'SKIPPED: no supported bug-tracker found' )
                    # Check thresholds/break build ?
                    break_build = False
                    if cxparams.has_thresholds() :

                        # Evaluate SAST
                        if cxparams.sast_threshold_new and counters['sast']['New'] >= cxparams.sast_threshold_new :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST New ' + str(counters['sast']['New']) + ' reached ' + str(cxparams.sast_threshold_new ) + ' limit!' )
                        if cxparams.sast_threshold_critical and counters['sast']['Critical'] >= cxparams.sast_threshold_critical :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST Critical ' + str(counters['sast']['Critical']) + ' reached ' + str(cxparams.sast_threshold_critical ) + ' limit!' )
                        if cxparams.sast_threshold_high and counters['sast']['High'] >= cxparams.sast_threshold_high :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST High ' + str(counters['sast']['High']) + ' reached ' + str(cxparams.sast_threshold_high ) + ' limit!' )
                        if cxparams.sast_threshold_medium and counters['sast']['Medium'] >= cxparams.sast_threshold_medium :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST Medium ' + str(counters['sast']['Medium']) + ' reached ' + str(cxparams.sast_threshold_medium ) + ' limit!' )
                        if cxparams.sast_threshold_low and counters['sast']['Low'] >= cxparams.sast_threshold_low :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SAST Low ' + str(counters['sast']['Low']) + ' reached ' + str(cxparams.sast_threshold_low ) + ' limit!' )

                        # Evaluate KICS
                        if cxparams.kics_threshold_new and counters['kics']['New'] >= cxparams.kics_threshold_new :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS New ' + str(counters['kics']['New']) + ' reached ' + str(cxparams.kics_threshold_new ) + ' limit!' )
                        if cxparams.kics_threshold_critical and counters['kics']['Critical'] >= cxparams.kics_threshold_critical :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS Critical ' + str(counters['kics']['Critical']) + ' reached ' + str(cxparams.kics_threshold_critical ) + ' limit!' )
                        if cxparams.kics_threshold_high and counters['kics']['High'] >= cxparams.kics_threshold_high :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS High ' + str(counters['kics']['High']) + ' reached ' + str(cxparams.kics_threshold_high ) + ' limit!' )
                        if cxparams.kics_threshold_medium and counters['kics']['Medium'] >= cxparams.kics_threshold_medium :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS Medium ' + str(counters['kics']['Medium']) + ' reached ' + str(cxparams.kics_threshold_medium ) + ' limit!' )
                        if cxparams.kics_threshold_low and counters['kics']['Low'] >= cxparams.kics_threshold_low :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, KICS Low ' + str(counters['kics']['Low']) + ' reached ' + str(cxparams.kics_threshold_low ) + ' limit!' )

                        # Evaluate SCA
                        if cxparams.sca_threshold_new and counters['sca']['New'] >= cxparams.sca_threshold_new :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA New ' + str(counters['sca']['New']) + ' reached ' + str(cxparams.sca_threshold_new ) + ' limit!' )
                        if cxparams.sca_threshold_critical and counters['sca']['Critical'] >= cxparams.sca_threshold_critical :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA Critical ' + str(counters['sca']['Critical']) + ' reached ' + str(cxparams.sca_threshold_critical ) + ' limit!' )
                        if cxparams.sca_threshold_high and counters['sca']['High'] >= cxparams.sca_threshold_high :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA High ' + str(counters['sca']['High']) + ' reached ' + str(cxparams.sca_threshold_high ) + ' limit!' )
                        if cxparams.sca_threshold_medium and counters['sca']['Medium'] >= cxparams.sca_threshold_medium :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA Medium ' + str(counters['sca']['Medium']) + ' reached ' + str(cxparams.sca_threshold_medium ) + ' limit!' )
                        if cxparams.sca_threshold_low and counters['sca']['Low'] >= cxparams.sca_threshold_low :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA Low ' + str(counters['sca']['Low']) + ' reached ' + str(cxparams.sca_threshold_low ) + ' limit!' )
                        if cxparams.sca_threshold_score and counters['sca']['CvsScore'] >= cxparams.sca_threshold_score :
                            break_build = True
                            cxlogger.verbose( 'THRESHOLD VIOLATION, SCA Highest CVSS Score ' + str(counters['sca']['CvsScore']) + ' reached ' + str(cxparams.sca_threshold_score ) + ' limit, package "' + counters['sca']['CvsScorePackage'] + '"!' )

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
