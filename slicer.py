import logging
# import subprocess
import enhanceLogging
import os
import fileCache
from misc import Lookahead, execute
import pygraphviz as pgv
from sys import maxint

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


def findParentSliceCanditate(trace, forkInsnNo, memoryLoc, cache=False):
    """Perform the stitching of slice to search for slice candidate in parent trace.

    Executes the following command
        findParentSliceCandidate <trace> <frame no of fork> <memorylocationofvariable>
    """
    logger = logging.getLogger(__name__)

    logger.info("Determining slice candidate of %s from %s for location %s", trace, forkInsnNo, memoryLoc)

    cmd = "findParentSliceCandidate {trace} {forkInsnNo} {memoryLoc}".format(trace=trace, forkInsnNo=forkInsnNo, memoryLoc=memoryLoc)

    rst = execute(cmd, cache)

    rst = rst.split()
    rst = ":".join(rst)

    if not rst or rst == "err:err":
        logger.error("Error in command: " + cmd)
        raise Exception("Error executing command: " + cmd)

    return rst


def get(trace, insn, index=0):
    """Fetch slice result from cache perform a slice
    """
    logger = logging.getLogger(__name__)

    logger.debug("Fetching slice result of {insn}:{index} from {trace}".format(trace=trace, insn=insn, index=index))
    slicedDFG = slice_cache.get((trace, insn, index), None)

    if slicedDFG is None:
        slicedDFG = slice(trace, insn, index)
        slice_cache[(trace, insn, index)] = slicedDFG

    return slicedDFG

def slice(trace, insn, index=0, arch=32, followToRoot=False):
    logger = logging.getLogger(__name__)



#     def isRegister(name):
#         if name[:2] == "R_":return True
#         return False



    if not followToRoot:
        logger.info("Performing single slice")
        return sliceSingle(trace, insn, index, arch)
    
    logger.info("Performing stitch slice")

    graph = sliceSingle(trace, insn, index, arch)

    g = pgv.AGraph(graph)

    vtx = g.nodes()
    for n in vtx:
        if not len(g.predecessors(n)):
            logger.debug("Root node of slice: {}".format(n))

            out_edges = g.out_edges(n)

            if len(out_edges) == 0:  # standalone
                raise Exception("Uninplemented")
            elif len(out_edges) == 1:  # register
                raise Exception("Uninplemented")
            else:

                min_addr = maxint
                min_addr_str = ""
                for e in out_edges:
                    current_addr = int(e.attr["label"], 16)
                    current_addr_str = e.attr["label"]
                    if min_addr > current_addr:
                        min_addr = current_addr
                        min_addr_str = current_addr_str

                logger.debug(min_addr_str)







    return g.to_string()

def sliceSingle(trace, insn, index=0, arch=32, cache=False):
    """Perform the slice and return the result as a string.

    Executes the following command
        binslicer-{arch} {trace} {insn}:0
    """
    logger = logging.getLogger(__name__)

    logger.info("Slicing %s at %s:%s", trace, insn, index)

    cmd = "binslicer-{arch} {trace} {insn}:{index}".format(arch=arch, trace=trace, insn=insn, index=index)

    rst = execute(cmd, cache)

    return rst

