import logging
# import subprocess
import enhanceLogging
import os
import fileCache
from misc import Lookahead, execute
import pygraphviz as pgv

slice_cache = {}

forkInfoLoaded = False



class Slice:
    def __init__(self, traceName, rootTrace, childTraces, mlfile):
        """
        Input
            traceName = value set in -o flag of gentrace
        """

        self.traceName = traceName
        self.rootTrace = rootTrace
        self.childTraces = childTraces
        self.mlfile = mlfile

        self.forkInfo = self.loadForkData(mlfile)


    def loadForkData(self, mlfile):
        logger = logging.getLogger(__name__)
        forkInfo = {}
        with open(mlfile) as f:

            for line in f:
                line = line.strip()
                l = line.split()
                if l[0] == "Spawning" and l[1] == "parent:":

                    forkname = l[3]
                    parentinsn = l[6]
                    forkInfo[forkname] = parentinsn
        return forkInfo

    def getName(self, tracename):
        logger = logging.getLogger(__name__)
        return tracename[:-len(self.traceName)]


    def getParentTraceName(self, tracename):
        logger = logging.getLogger(__name__)
        # print tracename, binaryName
        if not  tracename[-len(self.traceName):] == self.traceName:
            raise Exception("unable to determine parent trace name as trace name {} does not end with binary name {}".format(tracename, self.traceName))

        if tracename == self.rootTrace:  # No parent
            return None

        parentName = tracename[:-len(self.traceName)][:-1]

        parentInsnNo = self.forkInfo[parentName + "p"]

        while parentName[-1] == "p":
            parentName = parentName[:-1]

        if (parentName == "s"):
            return self.rootTrace, parentInsnNo

        return parentName + self.traceName, parentInsnNo

def findParentSliceCandidate(trace, forkInsnNo, memoryLoc, bindir=os.path.dirname(os.path.realpath(__file__)) + "/bin/", cache=False):
    """Perform the stitching of slice to search for slice candidate in parent trace.

    Executes the following command
        findParentSliceCandidate <trace> <frame no of fork> <memorylocationofvariable>
    """
    logger = logging.getLogger(__name__)

    logger.info("Determining slice candidate of %s from %s for location %s", trace, forkInsnNo, memoryLoc)

    cmd = "{bindir}findParentSliceCandidate {trace} {forkInsnNo} {memoryLoc}".format(trace=trace, forkInsnNo=forkInsnNo, memoryLoc=memoryLoc, bindir=bindir)

    rst = execute(cmd, cache)

    rst = rst.split()

    if not rst or rst[0] == "err":
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

def slice(trace, insn, index=0, arch=32, followToRoot=False, tname=None, sliceInfo=None, cache=False):
    logger = logging.getLogger(__name__)



#     def isRegister(name):
#         if name[:2] == "R_":return True
#         return False

    if not followToRoot:
        logger.info("Performing single slice")
        return sliceSingle(trace, insn, index, arch)

    logger.info("Performing stitch slice")

    graph = sliceSingle(trace, insn, index, arch, cache=cache)


    if tname is None:
        tname = sliceInfo.getName(trace)

    ret = pgv.AGraph(directed=True, strict=False)
    ret.node_attr.update(shape="box")
    g = pgv.AGraph(graph)

    for vtx in g.iternodes():
        ret.add_node("{}:{}".format(tname, vtx.name), label="{}:{}".format(tname, vtx.attr["label"]))

    for edge in g.iteredges():
        ret.add_edge("{}:{}".format(tname, edge[0]), "{}:{}".format(tname, edge[1]), key=None , **edge.attr)



    parentTrace = sliceInfo.getParentTraceName(trace)
    logger.info("Parent trace of {} is {}".format(trace, parentTrace))

    if parentTrace is not None:
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
                    min_addr = -1
                    min_addr_str = ""
                    for e in out_edges:
                        current_addr = int(e.attr["label"], 16)
                        current_addr_str = e.attr["label"]
                        if min_addr > current_addr or min_addr < 0:
                            min_addr = current_addr
                            min_addr_str = current_addr_str

                    logger.debug("Min addr of root node is {}".format(min_addr_str))
                    memoryLoc = min_addr_str


                sliceCandidate = findParentSliceCandidate(parentTrace[0], parentTrace[1], memoryLoc, cache=cache)
                logger.debug("Slice candidate {}".format(sliceCandidate))

                g2 = slice(parentTrace[0], sliceCandidate[0], sliceCandidate[1], followToRoot=followToRoot, tname=None, sliceInfo=sliceInfo, cache=cache)
                g2 = pgv.AGraph(g2)
                for vtx in g2.iternodes():
                    ret.add_node(vtx.name, **vtx.attr)

                for edge in g2.iteredges():
                    if edge[0] == edge[1]: continue
                    ret.add_edge(edge[0], edge[1], key=None , **edge.attr)

                # ret.add_node("{}:{}".format(tname, 0), label="{}:{}".format(tname, "0"))

                parentTraceHead = sliceInfo.getName(parentTrace[0])
                # ret.add_edge("{}:{}".format(parentTraceHead, sliceCandidate[0]), "{}:{}".format(parentTraceHead, parentTrace[1]), key=None, label=min_addr_str, color="red", style="bold")
                # ret.add_edge("{}:{}".format(parentTraceHead, parentTrace[1]), "{}:{}".format(tname, 0), key=None, label="passthru", color="blue", style="bold")
                # ret.add_edge("{}:{}".format(tname, 0), "{}:{}".format(tname, n), key=None, label=min_addr_str, color="red", style="bold")

                ret.add_edge("{}:{}".format(parentTraceHead, sliceCandidate[0]), "{}:{}".format(tname, n), key=None, label=min_addr_str, color="blue", style="bold")


    return ret.to_string()

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

def test():

    logging.basicConfig(level=enhanceLogging.DEBUG_LEVELV_NUM)

    mlfile = r"/vagrant/test/forktest/f4/f4.modload"
    # loadForkData(mlfile)




    rootTrace = "2914-f4.bpt"
    remaintraces = ["sccf4.bpt", "sccppccf4.bpt", "sccppcpccf4.bpt", "sccppcppcf4.bpt", "scccf4.bpt"   , "sccpcf4.bpt" , "sccppcf4.bpt"  , "sccppcpcf4.bpt", "scf4.bpt"]
    traceName = rootTrace.split("-", 1)[1]

    sliceInfo = Slice(traceName, rootTrace, remaintraces, mlfile)
    # print binaryName



    # for i in remaintraces:
    #   print i, "-->", sliceInfo.getName(i)
    print slice("sccppcf4.bpt", 2272, 0, followToRoot=True, sliceInfo=sliceInfo, cache=True)



test()
