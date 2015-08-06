import logging
import pygraphviz as pgv
import collections
import os
import subprocess
import slicer
import enhanceLogging

def isRegister(name):
    if name[:2] == "R_":return True
    return False

def isVPUsedToWriteV(trace, insn, bindir=os.path.dirname(os.path.realpath(__file__)) + "/bin/"):
    """
    Check if VP at insn is used to write to V at insn

    Input:
        trace - path to trace file
        insn - instruction no
        bindir - path to the directory containing bin

    Output:
        true/false
    """
    logger = logging.getLogger(__name__)

    cmd = "{0}isVPUsedToWriteV {1} {2}".format(bindir, trace, insn)
    logger.debug("Executing command: " + cmd)

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, close_fds=True)

    stdout = p.stdout
    with stdout as result:
        rst = result.read().strip()
    if not rst:
        logger.error("Error in command: " + cmd)
        raise Exception("Error executing command: " + cmd)

    logger.debug("Result: " + rst)
    if rst == "True":
        return True
    elif rst == "False":
        return False
    else:
        logger.error("Unknown return: " + rst)
        raise Exception("Unknown return: " + rst)

def isAliveAt(trace, start, end, address, bindir=os.path.dirname(os.path.realpath(__file__)) + "/bin/"):
    """
    Check address has been written to from insn start to insn end

    Input:
        trace - path to trace file
        start - first insn no
        end - last insn no
        address - memory address of value
        bindir - path to the directory containing bin

    Output:
        true/false
    """
    logger = logging.getLogger(__name__)

    cmd = "{bindir}isAliveAt {trace} {start} {address} {end}".format(bindir=bindir, trace=trace, start=start, end=end, address=address)
    logger.debug("Executing command: " + cmd)

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, close_fds=True)

    stdout = p.stdout
    with stdout as result:
        rst = result.read().strip()
    if not rst:
        logger.error("Error in command: " + cmd)
        raise Exception("Error executing command: " + cmd)

    logger.debug("Result: " + rst)

    adStatus = rst.split(" ", 1)

    if adStatus[0] == "True":
        return True
    elif adStatus[0] == "False":
        return False
    else:
        logger.error("Unknown return: " + rst)
        raise Exception("Unknown return: " + rst)

def getVPP(trace, insn, bindir=os.path.dirname(os.path.realpath(__file__)) + "/bin/"):
    """
    Get the address of vp for the memory access at insn

    Input:
        trace - path to trace file
        insn - instruction no of vp

    Output:
        (insn, address)
    """
    logger = logging.getLogger(__name__)

    cmd = "{bindir}getVPP {trace} {insn}".format(bindir=bindir, trace=trace, insn=insn)
    logger.debug("Executing command: " + cmd)

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, close_fds=True)

    stdout = p.stdout
    with stdout as result:
        rst = result.read().strip()
    if not rst:
        logger.error("Error in command: " + cmd)
        raise Exception("Error executing command: " + cmd)

    logger.debug("Result: " + rst)

    vppRst = rst.split(" ", 1)

    if vppRst[0] == "err":
        logger.error("Unknown return: " + rst)
        raise Exception("Unknown return: " + rst)
    return vppRst

def getEdges(graph, src):
    logger = logging.getLogger(__name__)
    # src = vS
    visited = {}
    que = collections.deque()
    try:
        src_node = graph.get_node(src)
    except KeyError:
        logger.error("Source address %s not found in trace.", src)
        raise Exception("Source address %s not found in trace.", src)


    que.append(src_node)
    result = []
    while que:
        child = que.pop()

        if visited.get(child, False):
            continue

        visited[child] = True
        c = int(child.name)


        edges = {}
        for parent_edge in graph.in_edges_iter(child):
            parentInsn = parent_edge[0]
            # if parentInsn == parent_edge[1]: continue  # Skip the last vtx pointing to itself

            edgesToParent = edges.get(parentInsn, None)
            if edgesToParent is None:
                que.append(parentInsn)
                edgesToParent = {}
                edges[parentInsn] = edgesToParent

            edgesToParent[parent_edge.attr["label"]] = parent_edge

            # yield parent_e

        for parent in edges.keys():
            # print edges[parent].keys()
            addr = min(edges[parent].keys())
            # for addr in edges[parent].keys():
            yield edges[parent][addr]


def runAlgo1(G, I, vT):
    """

    Input:
        G = benign trace
        vT = vT
        target = I

    """

    logger = logging.getLogger(__name__)
    logger.info("Determining corruption target for vT {0} I {1}.".format(vT, I))

    result = []

    tdslice = slicer.get(G, vT)

    TDFlow = pgv.AGraph(tdslice)

    for V in getEdges(TDFlow, vT):
        p = int(V[0])
        c = int(V[1])

        mem = V.attr["label"]
        if isRegister(mem): continue  # 4

        if p < I[0] and I[0] < c:
            logger.info("Possible edge: {} {} {}".format(p, c, mem))
            result.append([p, c, mem])

    return result


def runAlgo2(G, I, vS, vsi, vT, vti, cp):
    """

    Input:
        G = benign trace
        I = [error insn]
    """
# def runAlgo2():
    logger = logging.getLogger(__name__)

    # Begin input args
#     benign_trace = "inpt/scalign-wuftpd-skiplib-7.bpt"
#     benign_modload = "inpt/align-wuftpd-skiplib-7.bpt"
#     error_trace = "inpt/scalign-err-wuftpd-skiplib-5.bpt"
#     error_modload = "inpt/align-err-wuftpd-skiplib-5.bpt"
#
#
#
#     tdslice = "inpt/scalign-wuftpd-skiplib-7-1787632.dot"
#     sdslice = "inpt/0-slice-1787598.dot"
#
#     vT = 1787632
#     vS = 1787598
#
#
#     cp = 1123226
#     alignrst = (1106195, 37863)  # (insn, functno) result of align


    # End of inpt args

    tdtrace = G
    sdtrace = G

    tdslice = slicer.get(G, vT, vti)
    sdslice = slicer.get(G, vS, vsi)

    # memoryErrorPt = alignrst[0]

#     I = [alignrst[0]]
    # I = [errorInsn]


    SDFlow = pgv.AGraph(sdslice)
    TDFlow = pgv.AGraph(tdslice)

    print "Algo 2A"
    for V in getEdges(TDFlow, vT):
        p = int(V[0])
        c = int(V[1])

        mem = V.attr["label"]
        if isRegister(mem): continue  # 7

        if I[0] > c:  continue  # 8

        if isVPUsedToWriteV(tdtrace, c): continue  # 10

        vpp = getVPP(tdtrace, c)
        if vpp[0] in ["ESP", "EBP"]: continue  # Unable to determine vpp

        logger.info("Possible edge: {} {} {}".format(p, c, mem))

        for vs in getEdges(SDFlow, vS):
            logger.debug("proc SDFlow edge {} {}".format(vs, vs.attr["label"]))
            if isRegister(vs.attr["label"]): continue
            if not isAliveAt(tdtrace, int(vs[0]), c, vs.attr["label"]): continue

            print "VPP = {}, VP = {}, VP.addr = {},  VS = {}, VS.addr = {}".format(vpp, V, V.attr["label"], vs, vs.attr["label"])
            corruption_target = runAlgo1(G, I, vpp[0])
            if not corruption_target:
                print "single stitch candidates selection: faied to find"
            else:
                for l in corruption_target:
                    print "single stitch candidates selection: {edge}".format(edge=l)


    print "Algo 2B"
    for V in getEdges(SDFlow, vS):
        p = int(V[0])
        c = int(V[1])

        mem = V.attr["label"]
        if isRegister(mem): continue  # 15

        if p < min(I) :  continue  # 16

        if not isVPUsedToWriteV(sdtrace, c): continue  # 18

        vpp = getVPP(tdtrace, c)
        if vpp[0] in ["ESP", "EBP"]: continue  # Unable to determine vpp

        logger.info("Possible edge: {} {} {}".format(p, c, mem))
#
        # for vt in TDFlow.edges_iter():
        for vt in getEdges(TDFlow, vT):
            logger.debug("proc TDFlow edge {} {}".format(vt, vt.attr["label"]))
            if isRegister(vt.attr["label"]): continue

            vt_time = int(vt[0])
            vprime_time = int(vt[1])
            logger.debug("{} < {} < {} : {}".format(vt_time, c, vprime_time, vt_time < c and c < vprime_time))
            if not (vt_time < c and c < vprime_time): continue

            print "VPP = {}, VP = {}, VP.addr = {}, VT = {} VT.addr = {}".format(vpp, V, V.attr["label"], vt, vt.attr["label"])
            corruption_target = runAlgo1(G, I, vpp[0])
            if not corruption_target:
                print "single stitch candidates selection: faied to find"
            else:
                for l in corruption_target:
                    print "single stitch candidates selection: {edge}".format(edge=l)
