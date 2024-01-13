
from config import config
from .cxproperties import cxproperties


# Abstract base class, must override


class basefeedback(object) :

    def __init__(self) :
        self.config         = None      # Configuration data
        self.cxparams       = None      # Application params
        self.scandata       = None      # The scan data
        self.resultdata     = None      # The aggregated results


    def __init__(self, config: config, cxparams: cxproperties, scandata, resultdata ) :
        self.config       = config
        self.cxparams     = cxparams
        self.scandata     = scandata
        self.resultdata   = resultdata


    # Overrideable method
    def processfeedback(self) :
        return
    
