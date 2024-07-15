
from cxloghandler import cxlogger
from config import config
import os
import json



class cxproperties(object) :

    def __init__( self, config: config) :

        self.scanid                     = config.value( 'scanid' )
        
        # If scanid was supplyed as a file name, expect scan summary json and try parse it
        # Check if the scan id is to be taken from the AST-CLI json output
        # Comodity for CI/CD pipelines
        if '.' in str(self.scanid) :
            cli_outputfile = self.scanid
            self.scanid = None
            if os.path.isfile(cli_outputfile) :
                try :
                    with open(cli_outputfile) as f:
                        xdata = json.load(f)
                        # The scan summary
                        if 'ID' in xdata :
                            self.scanid = xdata['ID']
                except :
                    pass
        
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

        # Global settings
        # ---------------
        if config.haskey('cx-flow.break-build') :
            self.break_build            = config.value('cx-flow.break-build')
        else :
            self.break_build            = True
        # This comes from command line
        if  config.haskey('cx-flow.disable-break-build') :
            self.break_build            = False

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
        # Thresholds
        self.sast_threshold_new         = None
        self.sast_threshold_critical    = None
        self.sast_threshold_high        = None
        self.sast_threshold_medium      = None
        self.sast_threshold_low         = None
        

        # Kics filters
        # ------------
        self.kics_filter_severities     = None
        self.kics_filter_state          = None
        self.kics_filter_categories     = None
        # Thresholds
        self.kics_threshold_new         = None
        self.kics_threshold_critical    = None
        self.kics_threshold_high        = None
        self.kics_threshold_medium      = None
        self.kics_threshold_low         = None

        # SCA filters
        # -----------
        self.sca_filter_severities      = None
        self.sca_filter_state           = None
        self.sca_filter_cvsscore        = None
        self.sca_filter_dependency_type = None
        self.sca_filter_ignore_dev_test = None
        self.sca_filter_policyviolation = None
        self.sca_filter_exploitablepath = None
        # Thresholds
        self.sca_threshold_new          = None
        self.sca_threshold_score        = None
        self.sca_threshold_critical     = None
        self.sca_threshold_high         = None
        self.sca_threshold_medium       = None
        self.sca_threshold_low          = None

        # Have GLOBAL branch filters ?
        if config.haskey('cx-flow.branches') :
            value = config.value('cx-flow.branches')
            if value :
                self.filter_branches    = self.__process_param_list(value)
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
                aux = self.__process_param_list(value)
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
                aux    = self.__process_param_list(value)
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
                aux        = self.__process_param_list(value)
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
                self.sast_filter_categories    = self.__process_param_list(value)
                # String and lowercase everything
                self.sast_filter_categories = [str(x).lower() for x in self.sast_filter_categories]
                if len(self.sast_filter_categories) == 0 :
                    self.sast_filter_categories = None

        # Have SAST cwe filters ?
        if config.haskey('cx-flow.filter-cwe') :
            value = config.value('cx-flow.filter-cwe')
            if value :
                self.sast_filter_cwes          = self.__process_param_list(value)
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
                aux    = self.__process_param_list(value)
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
                aux        = self.__process_param_list(value)
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
                self.kics_filter_categories    = self.__process_param_list(value)
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
                aux    = self.__process_param_list(value)
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
                aux        = self.__process_param_list(value)
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
            self.sca_filter_cvsscore      = self.__process_param_list(value)
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

        # Have SCA dependency violation filter ?
        if config.haskey('sca.filter-policy-violation') :
            self.sca_filter_policyviolation = config.value('sca.filter-policy-violation')
            
        # Have SCA exploitable path filter ?
        if config.haskey('sca.filter-exploitable-path') :
            self.sca_filter_exploitablepath = config.value('sca.filter-exploitable-path')

        # Have SAST thresholds ?
        
        aux = None
        if config.haskey('cx-flow.thresholds') :
            aux = self.__process_thresholds_list( config.value('cx-flow.thresholds') )
        for ts in aux :
            tskey   = ts['k']
            tsval   = ts['v'] 
            if tskey == 'new' :
                self.sast_threshold_new         = int(tsval)
            elif tskey == 'critical' :
                self.sast_threshold_critical    = int(tsval)
            elif tskey == 'high' : 
                self.sast_threshold_high        = int(tsval)
            elif tskey == 'medium' :
                self.sast_threshold_medium      = int(tsval)
            elif tskey == 'low' :
                self.sast_threshold_low         = int(tsval)
                

        # Have KICS thresholds ?
        aux = None
        if config.haskey('kics.thresholds') :
            aux = self.__process_thresholds_list( config.value('kics.thresholds') )
        for ts in aux :
            tskey   = ts['k']
            tsval   = ts['v'] 
            if tskey == 'new' :
                self.kics_threshold_new         = int(tsval)
            elif tskey == 'critical' :
                self.kics_threshold_critical    = int(tsval)
            elif tskey == 'high' : 
                self.kics_threshold_high        = int(tsval)
            elif tskey == 'medium' :
                self.kics_threshold_medium      = int(tsval)
            elif tskey == 'low' :
                self.kics_threshold_low         = int(tsval)

        # Have SCA thresholds-score ?
        if config.haskey('sca.thresholds-score') :
            value = config.value('sca.thresholds-score')
            if (type(value) is int) or (type(value) is float) :      
                self.sca_threshold_score      = value
            else :
                self.sca_threshold_score      = None
        if self.sca_threshold_score :
            if self.sca_threshold_score > 10.0 :
                self.sca_threshold_score = 10.0

        # Have SCA thresholds ?
        aux = None
        if config.haskey('sca.thresholds') :
            aux = self.__process_thresholds_list( config.value('sca.thresholds') )
        elif config.haskey('sca.thresholds-severity') :
            aux = self.__process_thresholds_list( config.value('sca.thresholds-severity') )
        for ts in aux :
            tskey   = ts['k']
            tsval   = ts['v'] 
            if tskey == 'new' :
                self.sca_threshold_new          = int(tsval)
            elif tskey == 'critical' :
                self.sca_threshold_critical     = int(tsval)
            elif tskey == 'high' : 
                self.sca_threshold_high         = int(tsval)
            elif tskey == 'medium' :
                self.sca_threshold_medium       = int(tsval)
            elif tskey == 'low' :
                self.sca_threshold_low          = int(tsval)
                        

    def has_thresholds(self) :
        if self.sast_threshold_new or self.sast_threshold_critical or self.sast_threshold_high or self.sast_threshold_medium or self.sast_threshold_low or \
            self.kics_threshold_new or self.kics_threshold_critical or self.kics_threshold_high or self.kics_threshold_medium or self.kics_threshold_low or \
            self.sca_threshold_new or self.sca_threshold_score or self.sca_threshold_critical or self.sca_threshold_high or self.sca_threshold_medium or self.sca_threshold_low :
            return True
        else :
            return False
        
        
    def __process_param_list(self, value) :
        if not value :
            return None
        values = []
        if (type(value) is list) :
            values  = value
        elif (type(value) is str) :
            aux = str(value).strip()
            if aux.startswith('[') and aux.endswith(']') :
                aux = aux[1:-1]
            if ';' in aux :
                values = aux.split(';')
            else :
                values = aux.split(',')
        else :
            # Fallback, this may not work
            values = [value]
        if len(values) == 0 :
            values = None
        return values
        

    def __process_thresholds_list(self, value) :
        if not value :
            return None
        values = []
        if (type(value) is list) :
            for ts in value :
                tskey   = str(list(dict(ts).keys())[0]).lower()
                tsval   = ts[tskey] 
                if tsval and int(tsval) > 0 :
                    values.append( { 'k': tskey, 'v': tsval } )
        elif (type(value) is str)  :
            aux = str(value).lower().strip()
            if aux.startswith('[') and aux.endswith(']') :
                aux = aux[1:-1]
            if ';' in aux :
                auxe = aux.split(';')
            else :
                auxe = aux.split(',')
            for auxee in auxe :
                if ':' in auxee :
                    taux = auxee.split(':')
                elif ' ' in auxee :
                    taux = auxee.split(' ')
                elif '=' in auxee :
                    taux = auxee.split('=')
                else :
                    taux = []
                if len(taux) == 2 :
                    tskey = taux[0].strip()
                    tsval = taux[1].strip()
                if tsval and int(tsval) > 0 :
                    values.append( { 'k': tskey, 'v': tsval } )
        if len(values) == 0 :
            values = None
        return values

