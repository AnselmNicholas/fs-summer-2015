import logging
import os


def get(filename,function,args):  # TODO: add error checking
    """Load and save result to cache
    """
    
    logger = logging.getLogger(__name__)

    filename = "cache/" + filename

    logger.debug("Cache file name is " + filename)
    if os.path.exists(filename):
        logger.debug("Returning result from cache")
        with open(filename) as f:
            return f.read()
    else:
        rst = function(*args)
        logger.debug("Writing result to cache")
        with open(filename, "w") as f:
            f.write(rst)
            return rst

