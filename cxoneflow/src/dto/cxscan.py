
class cxscan(object) :
    
    def __init__(self) :
        self.id: str                = None
        self.scanid: str            = None
        self.status: str            = None
        self.statusdetails: list    = None
        self.branch: str            = None
        self.created: str           = None
        self.updated: str           = None        
        self.initiator: str         = None
        self.engines: list          = None
        self.sourcetype: str        = None
        self.sourceorigin: str      = None
        self.incremental: bool      = False
        self.loc: int               = None
        self.tags: list             = None
        self.tagstext: str          = None
        self.projectid: str         = None
        self.projectname: str       = None
        self.projecttags: list      = None
        self.projecttagstext: str   = None
        
        
    def updatescandata( self, scandata, projectdata ) :
        # Scan elements
        self.id                 = scandata['id']
        self.scanid             = scandata['id']
        self.status             = scandata['status']
        self.statusdetails      = scandata['statusDetails']
        self.branch             = scandata['branch']
        self.created            = scandata['createdAt']
        self.updated            = scandata['updatedAt']
        self.initiator          = scandata['initiator']
        self.engines            = scandata['engines']
        self.sourcetype         = scandata['sourceType']
        self.sourceorigin       = scandata['sourceOrigin']
        self.incremental        = False
        self.tags               = []
        self.tagstext           = None
        # Project elements
        self.projectid          = scandata['projectId']
        self.projectname        = scandata['projectName']
        self.projecttags        = []
        self.projecttagstext    = None
        # Check LOC on sast scans
        self.loc                = 0
        for status in scandata['statusDetails'] :
            if status['name'] == 'sast' :
                aux = status.get('loc')
                if aux: 
                    self.loc = int(aux)        
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
        
        