import logging
import subprocess
from interimCache import interimCache
import enhanceLogging
import os
class Lookahead:
    """Lookahead iterator for efficient parsing

    http://stackoverflow.com/a/1517965/1364256
    """
    def __init__(self, itera):
        self.iter = iter(itera)
        self.buffer = []

    def __iter__(self):
        return self

    def next(self):
        if self.buffer:
            return self.buffer.pop(0)
        else:
            return self.iter.next()

    def lookahead(self, n=0):
        """Return an item n entries ahead in the iteration."""
        while n >= len(self.buffer):
            try:
                self.buffer.append(self.iter.next())
            except StopIteration:
                return None
        return self.buffer[n]

def getTempFileName(cmd):
    cacheFolder = "tmp/"
    invalidChars = '\/:*?"<>|'

    item_final = []
    for i in cmd.split():
        i = i.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        for c in invalidChars:
            i = i.replace(c, "-")

        item_final.append(i)

    filename = "_".join(item_final) + ".tmp"
    fullpath = cacheFolder + filename

    if not os.path.exists(cacheFolder):
        try:
            os.makedirs(cacheFolder)
        except OSError as error:
            if error.errno != error.errno.EEXIST:
                raise


    logging.info("Cache file name generated {0}".format(fullpath))

    return fullpath

def execute(cmd, cache=False):

    # testing
    cache = True

    if (cache):
        ic = interimCache(cmd)
        if ic.exist(): return ic.load()

    rst = executeCommand(cmd)

    if (cache):
        ic.save(rst)

    return rst

def executeCommand(cmd):
    """Executes the input command
    """
    logger = logging.getLogger(__name__)

    logger.debug("Executing command: " + cmd)

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)

    stderr = p.stderr
    with stderr as err_result:
        err_rst = err_result.read().strip()
        logger.debugv("Result ERR:\n%s", err_rst)
    stdout = p.stdout
    with stdout as result:
        rst = result.read().strip()
        logger.debugv("Result:\n%s", rst)
    if not rst:
        logger.error("Error in command: " + cmd)
        raise Exception("Error executing command: " + cmd)

    return rst
