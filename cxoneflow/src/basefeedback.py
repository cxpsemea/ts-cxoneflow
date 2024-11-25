
from config import config
from .cxproperties import cxproperties
from .dto.cxscan import *
from .dto.cxresults import *
from .dto.cxcounters import *


# Abstract base class, must override


class basefeedback(object) :

    def __init__(self) :
        self.config         = None      # Configuration data
        self.cxparams       = None      # Application params
        self.scaninfo       = None      # The scan data
        self.results        = None      # The aggregated results
        self.counters       = None      # The elegible results count 
        self.countersall    = None      # The total results found


    def __init__(self, config: config, cxparams: cxproperties, scaninfo: cxscan, results: cxresults, counters: cxresultscounters, countersall: cxresultscounters ) :
        self.config         = config
        self.cxparams       = cxparams
        self.scaninfo       = scaninfo
        self.results        = results
        self.counters       = counters
        self.countersall    = countersall


    # Overrideable method
    def processfeedback(self) :
        return
    
