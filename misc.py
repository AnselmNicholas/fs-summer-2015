import logging
import subprocess
from interimCache import interimCache
import enhanceLogging

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

def execute(cmd, cache=False):
    
    #testing
    cache=True
    
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

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, close_fds=True)

    stdout = p.stdout
    with stdout as result:
        rst = result.read().strip()
        logger.debugv("Result:\n%s", rst)
    if not rst:
        logger.error("Error in command: " + cmd)
        raise Exception("Error executing command: " + cmd)

    return rst
