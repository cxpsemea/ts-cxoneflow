
# Results counter for scanner
class cxresultscounter(object) :

    def __init__(self, scanner: str, new: int = 0, recurrent: int = 0, 
                    critical: int = 0, high: int = 0, medium: int = 0, low: int = 0, info: int = 0,
                    cvsscore: int = 0, cvsscorepackage: str = None ) :
        self.scanner            = scanner
        self.new                = new
        self.recurrent          = recurrent
        self.critical           = critical
        self.high               = high
        self.medium             = medium
        self.low                = low
        self.info               = info
        self.cvsscore           = cvsscore
        self.cvsscorepackage    = cvsscorepackage

    def updatecount( self, scanresult ) :
        # Update counters
        if str(scanresult['status']).lower() == 'new' :
            self.new        += 1 
        else :
            self.recurrent  += 1
        if str(scanresult['severity']).lower() == 'critical' :
            self.critical   += 1
        elif str(scanresult['severity']).lower() == 'high' :
            self.high       += 1
        elif str(scanresult['severity']).lower() == 'medium' :
            self.medium     += 1
        elif str(scanresult['severity']).lower() == 'low' :
            self.low        += 1
        elif str(scanresult['severity']).lower() == 'info' :
            self.info       += 1
        # Special sca cvs        
        if self.scanner == 'sca' :
            score = scanresult['vulnerabilityDetails']['cvssScore']
            if score > self.cvsscore :
                self.cvsscore           = score
                self.cvsscorepackage    = scanresult['data']['packageIdentifier']
        
    
# Results counters for scanners    
class cxresultscounters(object) :

    def __init__(self) :
        self.sast   = cxresultscounter('sast')
        self.kics   = cxresultscounter('kics')
        self.sca    = cxresultscounter('sca')

    # Getter
    def getcounter( self, scanner: str ) :
        if scanner == 'sast' :
            return self.sast
        elif scanner == 'kics' :
            return self.kics
        elif scanner == 'sca' :
            return self.sca
        else :
            return None
            

        
    
