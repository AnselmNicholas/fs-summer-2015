import logging, os

class interimCache:
    cacheFolder = "cachez/"
    invalidChars = '\/:*?"<>|'
    def __init__(self, cmd):
        logger = logging.getLogger(__name__)

        self.cmd = cmd

        item_final = []
        for i in cmd.split():
            i = i.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            for c in self.invalidChars:
                i = i.replace(c,"-")
            
            item_final.append(i)

        self.filename = "_".join(item_final) + ".cache"
        self.fullpath = self.cacheFolder + self.filename

        logger.info("Cache object created {0}".format(self.fullpath))

    def exist(self):
        return os.path.isfile(self.fullpath)

    def load(self):
        logger = logging.getLogger(__name__)
        logger.info("Data loaded from cache {0}".format(self.fullpath))
        with open(self.fullpath) as f:
            ret = f.read()
        return ret

    def save(self, data):
        logger = logging.getLogger(__name__)
        logger.info("Data written to cache {0}".format(self.fullpath))

        if not os.path.exists(self.cacheFolder):
            try:
                os.makedirs(self.cacheFolder)
            except OSError as error:
                if error.errno != error.errno.EEXIST:
                    raise

        with open(self.fullpath, "w") as f:
            f.write(data)

