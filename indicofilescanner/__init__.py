from indico.core.plugins import IndicoPlugin
from add import do_add

class IndicoFileScannerPlugin(IndicoPlugin):
    """Indico File Scanner Plugin

    Scans uploaded files for viruses with ClamAV
    """
    configurable = False

    def init(self):
        super(IndicoFileScannerPlugin, self).init()
        do_add()


