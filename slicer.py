import logging
# import subprocess
import enhanceLogging
import os
from misc import Lookahead, execute
import pygraphviz as pgv
from tracereader.trace_container import TraceContainerReader

slice_cache = {}

class SliceInfo:
    def __init__(self, traceName, rootTrace, childTraces, mlfile):
        """
        Input
            traceName = value set in -o flag of gentrace
        """
        logger = logging.getLogger(__name__)

        self.traceName = traceName
        self.rootTrace = rootTrace
        self.childTraces = childTraces
        self.ml = mlfile

        if not mlfile == "":
            try:
                self.forkInfo = self.loadForkData(mlfile)
            except IndexError:
                logger.warn("Unable to load fork data")

    def canStitchSlice(self):
        try:
            self.forkInfo
            return len(self.childTraces)

        except AttributeError:
            return False

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

    def getTracePath(self, fileNameHeader):
        """return full path to a trace given the file name header"""

        inputFileName = fileNameHeader + self.traceName

        rootTraceName = self.rootTrace.split("/")[-1].split("\\")[-1]
        if rootTraceName == inputFileName:
            return rootTraceName

        for childTraceName in self.childTraces:
            ctn = childTraceName.split("/")[-1].split("\\")[-1]
            if ctn == inputFileName:
                return childTraceName

        raise Exception("Trace not found")

    def getNameK(self, param):
        """Returns file name header of the trace

        Input
            param: index of child trace or `p`
        """
        return self.getName(self.getTrace(param))

    def getName(self, tracename):
        """Returns file name header of the trace

        Input
            tracename: name of trace file
        """
        logger = logging.getLogger(__name__)

        tracename = tracename.split("/")[-1].split("\\")[-1]

        return tracename[:-len(self.traceName)]

    def getParent(self, fileNameHeader):
        """
        get parent info given file header
        returns <full path to tracee>, fork insn
        """

        parentNameHeader = fileNameHeader[:-1]

        parentInsnNo = self.forkInfo[parentNameHeader + "p"]

        while parentNameHeader[-1] == "p":
            parentNameHeader = parentNameHeader[:-1]

        if (parentNameHeader == "s"):
            return self.rootTrace, parentInsnNo

        return self.getTracePath(parentNameHeader), parentInsnNo


    def getParentTraceName(self, tracename):
        """
        get parent info given file name
        returns <full path to tracee>, fork insn
        """
        logger = logging.getLogger(__name__)
        # print tracename, binaryName

        tracename = tracename.split("/")[-1].split("\\")[-1]

        if not  tracename[-len(self.traceName):] == self.traceName:
            raise Exception("unable to determine parent trace name as trace name {} does not end with binary name {}".format(tracename, self.traceName))

        if tracename == self.rootTrace:  # No parent
            return None

        fileNameHeader = tracename[:-len(self.traceName)]


        return self.getParent(fileNameHeader)

    def getTrace(self, param):
        return self.rootTrace if param == "p" else self.childTraces[int(param)]

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


def get(trace, insn, index=0, sliceStitch=False, sliceInfo=None):
    """Fetch slice result from cache perform a slice
    """
    logger = logging.getLogger(__name__)

    logger.debug("Fetching slice result of {insn}:{index} from {trace} slice-stitch is {ss}".format(trace=trace, insn=insn, index=index, ss=sliceStitch))
    slicedDFG = slice_cache.get((trace, insn, index, sliceStitch), None)

    if slicedDFG is None:
        slicedDFG = slice(trace, insn, index, followToRoot=sliceStitch, sliceInfo=sliceInfo)
        slice_cache[(trace, insn, index, sliceStitch)] = slicedDFG

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

#     print insn
#     itname , insn = insn.split(":", 1)
    graph = sliceSingle(trace, insn, index, arch, cache=cache)


    if tname is None:
        tname = sliceInfo.getName(trace)
#         assert tname == itname

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
                    tcr = TraceContainerReader(trace)
                    tcr.seek(int(n))
                    f = tcr.get_frame()

                    min_addr = -1
                    for elem in f.std_frame.operand_pre_list.elem:
                        if not elem.operand_info_specific.HasField("mem_operand"): continue
                        if not elem.operand_usage.read: continue

                        current_addr = elem.operand_info_specific.mem_operand.address
                        if min_addr > current_addr or min_addr < 0:
                            min_addr = current_addr

                    min_addr_str = format(min_addr, "x")



                else:
                    min_addr = -1
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

                ret.add_edge("{}:{}".format(parentTraceHead, sliceCandidate[0]), "{}:{}".format(tname, n), key=None, label="passtru:{}:{}".format(min_addr_str, parentTrace[1]), color="blue", style="bold")


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
