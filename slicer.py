import logging
import subprocess
import enhanceLogging
import os
import fileCache
from misc import Lookahead

slice_cache = {}


forkInfoLoaded = False
forkInfo = {}

def loadForkData(mlfile):
    logger = logging.getLogger(__name__)
    with open(mlfile) as f:

        for line in f:
            line = line.strip()
            l = line.split()
            if l[0] == "Spawning" and l[1] == "parent:":

                forkname = l[3]
                parentinsn = l[6]
                forkInfo[forkname] = parentinsn

def getParentTraceName(tracename, binaryName):
    logger = logging.getLogger(__name__)
    # print tracename, binaryName
    if not  tracename[-len(binaryName):] == binaryName:
        raise Exception("unable to determine parent trace name as trace name {} does not end with binary name {}".format(tracename, binaryName))

    parentName = tracename[:-len(binaryName)][:-1]

    parentInsnNo = forkInfo[parentName + "p"]

    while parentName[-1] == "p":
        parentName = parentName[:-1]

    return parentName + binaryName, parentInsnNo


def findParentSliceCanditate(trace, forkInsnNo, memoryLoc):
    """Perform the stitching of slice to search for slice candidate in parent trace.

    Executes the following command
        findParentSliceCandidate <trace> <frame no of fork> <memorylocationofvariable>
    """
    logger = logging.getLogger(__name__)

    logger.info("Determining slice candidate of %s from %s for location %s", trace, forkInsnNo, memoryLoc)

    cmd = "findParentSliceCandidate {trace} {forkInsnNo} {memoryLoc}".format(trace=trace, forkInsnNo=forkInsnNo, memoryLoc=memoryLoc)
    logger.debug("Executing command: " + cmd)


    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, close_fds=True)

    stdout = p.stdout
    with stdout as result:
        rst = result.read().strip()
        logger.debugv("Result:\n%s", rst)

    rst = rst.split()
    rst = ":".join(rst)

    if not rst or rst == "err:err":
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

def slice(trace, insn, index=0, arch=32, followToRoot=False):
    if not followToRoot:
        return sliceSingle(trace, insn, index, arch)

def sliceSingle(trace, insn, index=0, arch=32):
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

def test():
    mlfile = r"/share/test/forktest/f4/f4.modload"
    loadForkData(mlfile)



    rootTrace = "2914-f4.bpt"
    remaintraces = ["sccf4.bpt", "sccppccf4.bpt", "sccppcpccf4.bpt", "sccppcppcf4.bpt", "scccf4.bpt"   , "sccpcf4.bpt" , "sccppcf4.bpt"  , "sccppcpcf4.bpt", "scf4.bpt"]
    binaryName = rootTrace.split("-", 1)[1]
    #print binaryName



    #for i in remaintraces:
    #    print i, "-->", getParentTraceName(i, binaryName)

    print slice("sccppcf4.bpt", 2272, 0, followToRoot=True)



test()
