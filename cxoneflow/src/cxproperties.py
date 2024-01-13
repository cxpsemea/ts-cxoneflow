
from cxloghandler import cxlogger
from config import config


class cxproperties(object) :

    def __init__( self, config: config) :

        self.scanid                     = config.value( 'scanid' )
        
        self.ticketkeyname              = 'TICKET_KEY'

        self.application                = config.value( 'app' )
        self.namespace                  = config.value( 'namespace' )
        self.repository                 = config.value( 'repository' )
        self.repo_url                   = config.value( 'repo-url' )
        self.branch                     = config.value( 'branch' )
        self.cxproject                  = config.value( 'cx-project' )            

        # The bug tracker        
        self.bug_tracker                = config.value('cx-flow.bug-tracker')
        if self.bug_tracker :
            self.bug_tracker            = str(self.bug_tracker).lower()

        self.cxurl                      = config.value('cxone.url')     
        if self.cxurl :
            self.cxurl = str(self.cxurl).rstrip('/')
        self.mitre_url                  = config.value('cx-flow.mitre-url')     #mitre-url: https://cwe.mitre.org/data/definitions/%s.html
        self.wiki_url                   = config.value('cx-flow.wiki-url')      #wiki-url: https://custodela.atlassian.net/wiki/spaces/AS/pages/79462432/Remediation+Guidance

        # Global filters 
        # --------------
        self.filter_scanners            = None
        self.filter_branches            = None

        # Sast filters
        # ------------
        self.sast_filter_severities     = None
        self.sast_filter_state          = None
        self.sast_filter_categories     = None
        self.sast_filter_cwes           = None

        # Kics filters
        # ------------
        self.kics_filter_severities     = None
        self.kics_filter_state          = None
        self.kics_filter_categories     = None

        # SCA filters
        # -----------
        self.sca_filter_severities      = None
        self.sca_filter_state           = None
        self.sca_filter_cvsscore        = None
        self.sca_filter_dependency_type = None
        self.sca_filter_ignore_dev_test = None

#   filter-policy-violation: true
#   //If User want to check for Direct Dependency specifically below tag can be used and default value is All. 
#   filter-dependency-type: Direct
#   //Based on threshold severity it will break build even for Direct Dependency.
#   thresholds-Severity:
#     HIGH: 1
#     MEDIUM: 150
#     LOW: 1        


        # Have GLOBAL branch filters ?
        if config.haskey('cx-flow.branches') :
            value = config.value('cx-flow.branches')
            if value :
                if (type(value) is list) :      
                    self.filter_branches    = value
                else :
                    self.filter_branches    = [value]
                # String and lowercase everything
                self.filter_branches = [str(x).lower() for x in self.filter_branches]
                if len(self.filter_branches) == 0 :
                    self.filter_branches = None

        # Have GLOBAL scanners filter ?
        if config.haskey('cx-flow.enabled-vulnerability-scanners') :
            value = config.value('cx-flow.enabled-vulnerability-scanners')
            aux = []
            self.filter_scanners = []
            if value :
                if (type(value) is list) :      
                    aux        = value
                else :
                    aux        = [value]
                # String and lowercase everything
                for xvalue in aux :
                    xvalue = str(xvalue).lower()
                    if xvalue == 'iac' :
                        xvalue = 'kics'
                    self.filter_scanners.append(xvalue)
                if len(self.filter_scanners) == 0 :
                    self.filter_scanners = None
        # If empty, use scanners SAST and SCA only, for compatibility
        if not self.filter_scanners :
            self.filter_scanners      = ['sast','sca']    # ['sast','sca','kics']

        # Have SAST severity filters ?
        # CRITICAL
        # HIGH
        # MEDIUM
        # LOW
        # INFO
        if config.haskey('cx-flow.filter-severity') :
            aux = []
            self.sast_filter_severities = []
            value = config.value('cx-flow.filter-severity')
            if value :
                if (type(value) is list) :      
                    aux    = value
                else :
                    aux    = [value]
                # String and lowercase everything
                for xvalue in aux :
                    xvalue = str(xvalue).lower()
                    if xvalue == 'information' :
                        xvalue = 'info'
                    self.sast_filter_severities.append(xvalue)
                if len(self.sast_filter_severities) == 0 :
                    self.sast_filter_severities = None

        # Have SAST state filters ?
        # TO_VERIFY
        # PROPOSED_NOT_EXPLOITABLE
        # NOT_EXPLOITABLE
        # URGENT
        # CONFIRMED
        if config.haskey('cx-flow.filter-status') :
            value = config.value('cx-flow.filter-status')
            aux = []
            self.sast_filter_state = []
            if value :
                if (type(value) is list) :      
                    aux        = value
                else :
                    aux        = [value]
                # String and lowercase everything
                for xvalue in aux :
                    xvalue = str(xvalue).lower()
                    if xvalue == 'to verify' :
                        xvalue = 'to_verify'
                    if xvalue == 'proposed not exploitable' :
                        xvalue = 'proposed_not_exploitable'
                    if xvalue == 'not exploitable' :
                        xvalue = 'not_exploitable'
                    self.sast_filter_state.append(xvalue)
                if len(self.sast_filter_state) == 0 :
                    self.sast_filter_state = None

        # Have SAST category filters ?
        if config.haskey('cx-flow.filter-category') :
            value = config.value('cx-flow.filter-category')
            if value :
                if (type(value) is list) :      
                    self.sast_filter_categories    = value
                else :
                    self.sast_filter_categories    = [value]
                # String and lowercase everything
                self.sast_filter_categories = [str(x).lower() for x in self.sast_filter_categories]
                if len(self.sast_filter_categories) == 0 :
                    self.sast_filter_categories = None

        # Have SAST cwe filters ?
        if config.haskey('cx-flow.filter-cwe') :
            value = config.value('cx-flow.filter-cwe')
            if value :
                if (type(value) is list) :      
                    self.sast_filter_cwes          = value
                else :
                    self.sast_filter_cwes          = [value]
                # String and lowercase everything
                self.sast_filter_cwes = [str(x).lower() for x in self.sast_filter_cwes]
                if len(self.sast_filter_cwes) == 0 :
                    self.sast_filter_cwes = None



        # Have KICS severity filters ?
        # CRITICAL
        # HIGH
        # MEDIUM
        # LOW
        # INFO
        if config.haskey('kics.filter-severity') :
            aux = []
            self.kics_filter_severities = []
            value = config.value('kics.filter-severity')
            if value :
                if (type(value) is list) :      
                    aux    = value
                else :
                    aux    = [value]
                # String and lowercase everything
                for xvalue in aux :
                    xvalue = str(xvalue).lower()
                    if xvalue == 'information' :
                        xvalue = 'info'
                    self.kics_filter_severities.append(xvalue)
                if len(self.kics_filter_severities) == 0 :
                    self.kics_filter_severities = None

        # Have KICS state filters ?
        # TO_VERIFY
        # PROPOSED_NOT_EXPLOITABLE
        # NOT_EXPLOITABLE
        # URGENT
        # CONFIRMED
        if config.haskey('kics.filter-status') :
            value = config.value('kics.filter-status')
            aux = []
            self.kics_filter_state = []
            if value :
                if (type(value) is list) :      
                    aux        = value
                else :
                    aux        = [value]
                # String and lowercase everything
                for xvalue in aux :
                    xvalue = str(xvalue).lower()
                    if xvalue == 'to verify' :
                        xvalue = 'to_verify'
                    if xvalue == 'proposed not exploitable' :
                        xvalue = 'proposed_not_exploitable'
                    if xvalue == 'not exploitable' :
                        xvalue = 'not_exploitable'
                    self.kics_filter_state.append(xvalue)
                if len(self.kics_filter_state) == 0 :
                    self.kics_filter_state = None


        # Have KICS category filters ?
        if config.haskey('kics.filter-category') :
            value = config.value('kics.filter-category')
            if value :
                if (type(value) is list) :      
                    self.kics_filter_categories    = value
                else :
                    self.kics_filter_categories    = [value]
                # String and lowercase everything
                self.kics_filter_categories = [str(x).lower() for x in self.kics_filter_categories]
                if len(self.kics_filter_categories) == 0 :
                    self.kics_filter_categories = None




        # Have SCA severity filters ?
        # CRITICAL
        # HIGH
        # MEDIUM
        # LOW
        # INFO
        if config.haskey('sca.filter-severity') :
            aux = []
            self.sca_filter_severities = []
            value = config.value('sca.filter-severity')
            if value :
                if (type(value) is list) :      
                    aux    = value
                else :
                    aux    = [value]
                # String and lowercase everything
                for xvalue in aux :
                    xvalue = str(xvalue).lower()
                    if xvalue == 'information' :
                        xvalue = 'info'
                    self.sca_filter_severities.append(xvalue)
                if len(self.sca_filter_severities) == 0 :
                    self.sca_filter_severities = None

        # Have SCA state filters ?
        # TO_VERIFY
        # PROPOSED_NOT_EXPLOITABLE
        # NOT_EXPLOITABLE
        # URGENT
        # CONFIRMED
        if config.haskey('sca.filter-status') :
            value = config.value('sca.filter-status')
            aux = []
            self.sca_filter_state = []
            if value :
                if (type(value) is list) :      
                    aux        = value
                else :
                    aux        = [value]
                # String and lowercase everything
                for xvalue in aux :
                    xvalue = str(xvalue).lower()
                    if xvalue == 'to verify' :
                        xvalue = 'to_verify'
                    if xvalue == 'proposed not exploitable' :
                        xvalue = 'proposed_not_exploitable'
                    if xvalue == 'not exploitable' :
                        xvalue = 'not_exploitable'
                    self.sca_filter_state.append(xvalue)
                if len(self.sca_filter_state) == 0 :
                    self.sca_filter_state = None
      
        # Have SCA score filter ?
        if config.haskey('sca.filter-score') :
            value = config.value('sca.filter-score')
            if (type(value) is int) or (type(value) is float) :      
                self.sca_filter_cvsscore      = value
            else :
                self.sca_filter_cvsscore      = None
        if self.sca_filter_cvsscore :
            if self.sca_filter_cvsscore > 10.0 :
                self.sca_filter_cvsscore = 10.0

        # Have SCA dependency type filter ?
        if config.haskey('sca.filter-dependency-type') :
            value = config.value('sca.filter-dependency-type')
            if value : 
                self.sca_filter_dependency_type = str(value).lower()

        # Have SCA ignore dev and test dependencies filter ?
        if config.haskey('sca.filter-ignore-dev-test') :
            value = config.value('sca.filter-ignore-dev-test')
            if str(value).lower() in ['true','yes','1'] :
                self.sca_filter_ignore_dev_test = True
            else :
                self.sca_filter_ignore_dev_test = None
        

#   filter-dependency-type: Direct