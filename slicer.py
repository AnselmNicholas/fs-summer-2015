import logging
import subprocess
import enhanceLogging
import os
import fileCache

slice_cache = {}
print "Init slice cache"

def get(trace, insn, index=0):
    """Fetch slice result from cache perform a slice
    """
    logger = logging.getLogger(__name__)

    logger.debug("Fetching slice result of {insn}:{index} from {trace}".format(trace=trace, insn=insn, index=index))
    slicedDFG = slice_cache.get((trace, insn, index), None)

    if slicedDFG is None:
        slicedDFG = cacheSliceToFile(trace, insn, index)
        slice_cache[(trace, insn, index)] = slicedDFG

    return slicedDFG


# def cacheSliceToFile(trace, insn, index=0, arch=32, cache=True):  # TODO: add error checking
#     """Load and save result to cache
#     """
#     logger = logging.getLogger(__name__)
#     logger.debug("Use file cache %s", cache)
#     if not cache:
#         return slice(trace, insn, index, arch)
#
#
#     filename = "slicer-{arch}-{trace}-{insn}-{index}.slice".format(arch=arch, trace=trace, insn=insn, index=index)
#     filename = "cache/" + filename
#     logger.debug("Cache file name is " + filename)
#     if os.path.exists(filename):
#         logger.debug("Returning result from cache")
#         with open(filename) as f:
#             return f.read()
#     else:
#         rst = slice(trace, insn, index, arch)
#         logger.debug("Writing result to cache")
#         with open(filename, "w") as f:
#             f.write(rst)
#             return rst

def cacheSliceToFile(trace, insn, index=0, arch=32, cache=True):  # TODO: add error checking
    """Load and save result to cache
    """
    logger = logging.getLogger(__name__)
    logger.debug("Use file cache %s", cache)
    if not cache:
        return slice(trace, insn, index, arch)


    filename = "slicer-{arch}-{trace}-{insn}-{index}.slice".format(arch=arch, trace=trace, insn=insn, index=index)

    return fileCache.get(filename, slice, (trace, insn, index, arch))



def slice(trace, insn, index=0, arch=32):
    """Perform the slice and return the result as a string.

    Executes the following command
        binslicer-{arch} {trace} {insn}:0
    """
    logger = logging.getLogger(__name__)

    logger.info("Slicing %s at %s:%s", trace, insn, index)

    cmd = "binslicer-{arch} {trace} {insn}:{index}".format(arch=arch, trace=trace, insn=insn, index=index)
    logger.debug("Executing command: " + cmd)


    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, close_fds=True)

    stdout = p.stdout
    with stdout as result:
        rst = result.read().strip()
        logger.debugv("Result:\n%s", rst)
    if not rst:
        logger.error("Error in command: " + cmd)
        raise Exception("Error executing command: " + cmd)
    
#     p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)

#     stdout = p.stdout
#     stderr = p.stderr
#     with stdout as result:
#         with stderr as err:
#             errTxt = err.read()
#             if errTxt:
#                 logger.error("Error in command:\n" + errTxt)
#                 raise Exception("Error executing command: " + cmd)

#         rst = result.read()
#         logger.debugv("Result:\n%s", rst)

    return rst
