
class cxscan(object) :
    
    def __init__(self) :
        self.id: str                = None
        self.scanid: str            = None
        self.status: str            = None
        statusDetails: list         = None
        self.branch: str            = None
        self.createdAt: str         = None
        self.updatedAt: str         = None        
        self.initiator: str         = None
        self.engines: list          = None
        self.sourceType: str        = None
        self.sourceOrigin: str      = None
        self.incremental: bool      = False
        self.tags: list             = None
        self.tagstext: str          = None
        self.projectId: str         = None
        self.projectName: str       = None
        self.projecttags: list      = None
        self.projecttagstext: str   = None
        
        
    def updatescandata( self, scandata, projectdata ) :
        # Scan elements
        self.id                 = scandata['id']
        self.scanid             = scandata['id']
        self.status             = scandata['status']
        self.statusDetails      = scandata['statusDetails']
        self.branch             = scandata['branch']
        self.createdAt          = scandata['createdAt']
        self.updatedAt          = scandata['updatedAt']
        self.initiator          = scandata['initiator']
        self.engines            = scandata['engines']
        self.sourceType         = scandata['sourceType']
        self.sourceOrigin       = scandata['sourceOrigin']
        self.incremental        = False
        self.tags               = []
        self.tagstext           = None
        # Project elements
        self.projectId          = scandata['projectId']
        self.projectName        = scandata['projectName']
        self.projecttags        = []
        self.projecttagstext    = None
        # Check if sast scan was incremental
        if ('sast' in scandata['engines']) and scandata['metadata']['configs'] :
            sastconfigs = next( filter( lambda el: el['type'] == 'sast', scandata['metadata']['configs'] ), None )
            for value in sastconfigs.values() :
                if 'incremental' in value :
                    self.incremental = value['incremental']
        # Process scan tags
        self.tags   = []
        tagstext    = ''
        scantags    = scandata['tags']
        tagkeys     = list(scantags.keys())
        if tagkeys and len(tagkeys) > 0 :
            tagname = tagkeys[0]
            tagvalue = scantags[tagkeys[0]]
            if not tagvalue :
                tagvalue = tagname
            self.tags.append( { 'name': tagname, 'value': tagvalue } )
            if tagstext :
                tagstext = tagstext + ', '
            tagstext = tagstext + tagname + ': ' + tagvalue
        self.tagstext = tagstext
        # Process project tags
        tagstext = ''
        projecttags = projectdata['tags']
        tagkeys = list(projecttags.keys())
        if tagkeys and len(tagkeys) > 0 :
            tagname = tagkeys[0]
            tagvalue = projecttags[tagkeys[0]]
            if not tagvalue :
                tagvalue = tagname
            self.projecttags.append( { 'name': tagname, 'value': tagvalue } )
            if tagstext :
                tagstext = tagstext + ', '
            tagstext = tagstext + tagname + ': ' + tagvalue
        self.projecttagstext = tagstext
        
        