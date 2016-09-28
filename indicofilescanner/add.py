from MaKaC.webinterface.rh.conferenceBase import RHSubmitMaterialBase
from indico.core.logger import Logger


def do_add():


    def monkey_setErrorList(fn):
        def new_funct(*args, **kwargs):
            ret = fn(*args, **kwargs)
            self = args[0]
            fileEntry = args[1]

            # Do not let file upload if the ClamAV check is not available
            try:
                import pyclamd
                pyclamd.ClamdAgnostic()
                Logger.get('FileScanner').info("ClamAV daemon found.")
            except ValueError as e:
                Logger.get('FileScanner').warning(e)
                self._errorList.append("File upload FAILED: Unable to check for Viruses: %s" % (e))
            except:
                Logger.get('FileScanner').warning("Unable to import pyclamd. No files will be scanned.")
                self._errorList.append("File upload FAILED: Unable to check for Viruses.")
            else:
                # If no other errors has been found, check for viruses
                if not self._errorList and self._uploadType == "file":
                    cd = pyclamd.ClamdAgnostic()
                    av_result = cd.scan_file(fileEntry["filePath"])
                    if av_result is not None:
                        # Virus found
                        virus_desc = str(av_result[fileEntry["filePath"]][1])
                        self._errorList.append("Virus found: " + virus_desc)
                        Logger.get('FileScanner').warning("Virus Found: %s" % (virus_desc))
        return new_funct

    RHSubmitMaterialBase._setErrorList = monkey_setErrorList(RHSubmitMaterialBase._setErrorList)


