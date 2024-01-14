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
            cxxoneconn.checkpermissions( perm_cxone = True, perm_accesscontrol = False )

            has_results = False
            scandata    = None
            counters    = None
            results     = None

            # Process scan results
            runner = cxprocessor( self.config, cxxoneconn, cxparams )
            has_results = runner.processscan()

            if has_results :
                scandata    = runner.scan
                counters    = runner.counters
                results     = runner.results

                if results['sast'] or results['sca'] or results['kics'] :
                    if cxparams.bug_tracker == 'jira' :
                        feeder = jirafeedback( self.config, cxparams, scandata, results )
                    feeder.processfeedback()
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
