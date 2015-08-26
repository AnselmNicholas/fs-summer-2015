import logging
import pygraphviz as pgv
import collections
import os
# import subprocess
import slicer
import enhanceLogging
from misc import execute

def isRegister(name):
    if name[:2] == "R_":return True
    return False

def isVPUsedToWriteV(trace, insn, bindir=os.path.dirname(os.path.realpath(__file__)) + "/bin/", cache=False):
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

    rst = execute(cmd, cache)

    if rst == "True":
        return True
    elif rst == "False":
        return False
    else:
        logger.error("Unknown return: " + rst)
        raise Exception("Unknown return: " + rst)

def isAliveAt(trace, start, end, address, sliceStitch=False, sliceInfo=None, bindir=os.path.dirname(os.path.realpath(__file__)) + "/bin/", cache=False):
    if not sliceStitch:
        return isAliveAtBin(trace, start, end, address, bindir=bindir, cache=cache)

    startt, start = start
    startt = sliceInfo.getTracePath(startt)
    endt, end = end
    endt = sliceInfo.getTracePath(endt)

    while not startt == endt:
        if not isAliveAtBin(endt, 0, end, address, bindir=bindir, cache=cache): return False
        endt, end = sliceInfo.getParentTraceName(endt)

    return isAliveAtBin(endt, start, end, address, bindir=bindir, cache=cache)


def isAliveAtBin(trace, start, end, address, bindir=os.path.dirname(os.path.realpath(__file__)) + "/bin/", cache=False):
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

    rst = execute(cmd, cache)

    adStatus = rst.split(" ", 1)

    if adStatus[0] == "True":
        return True
    elif adStatus[0] == "False":
        return False
    else:
        logger.error("Unknown return: " + rst)
        raise Exception("Unknown return: " + rst)

def getVPP(trace, insn, bindir=os.path.dirname(os.path.realpath(__file__)) + "/bin/", cache=False):
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

    rst = execute(cmd, cache)

    vppRst = rst.split(" ", 1)

    if vppRst[0] == "err":
        logger.error("VPP not found: " + rst)
        raise Exception("VPP not found: " + rst)
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
    while que:
        child = que.pop()

        if visited.get(child, False):
            continue

        visited[child] = True
        # c = int(child.name)


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


def runAlgo1(G, I, vT, sliceStitch=False, sliceInfo=None):
    """

    Input:
        G = benign trace
        vT = vT
        target = I

    """

    logger = logging.getLogger(__name__)
    logger.info("Determining corruption target for vT {0} I {1}.".format(vT, I))

    result = []

    vTi = vT
    vTs = vT
    if sliceStitch:
        _, vTi = vT
        vTs = "{}:{}".format(*vT)
    tdslice = slicer.get(G, vTi, sliceStitch=sliceStitch, sliceInfo=sliceInfo)

    TDFlow = pgv.AGraph(tdslice)

    if sliceStitch:
        it, i = I[0]
    else:
        i = I[0]



    for V in getEdges(TDFlow, vTs):
        if sliceStitch:
            po = V[0]
            pt, p = po.split(":", 1)
            p = int(p)
            co = V[1]
            ct, c = co.split(":", 1)
            c = int(c)

            mem = V.attr["label"]
            passtru = False
            if mem.startswith("passtru"):  # passtru:805c800:1089664
                _, mem, forkins = mem.split(":", 2)
                passtru = True

        else:
            p = int(V[0])
            c = int(V[1])
            mem = V.attr["label"]



        if isRegister(mem): continue  # 4

        if sliceStitch:
            if passtru:
                if pt == it and p < i and i < forkins:
                    logger.info("Possible edge in parent: {} {} {}".format(po, co, mem))
                    result.append([po, co, mem])
                elif ct == it and i < c:  # 0 < i is assumed to be true
                    logger.info("Possible edge in child: {} {} {}".format(po, co, mem))
                    result.append([po, co, mem])

            else:  # do like normal except check trace name as well
                if pt == it and p < i and i < c:
                    logger.info("Possible edge: {} {} {}".format(po, co, mem))
                    result.append([po, co, mem])
        else:
            if p < i and i < c:
                logger.info("Possible edge: {} {} {}".format(p, c, mem))
                result.append([p, c, mem])

    return result


def runAlgo2(Gt, I, vS, vsi, vT, vti, cp, Gs=None, sliceStitch=False, sliceInfo=None):
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

    tdtrace = Gt
    sdtrace = Gs if not Gs == None else Gt



    vTi = vT
    vTs = vT
    vSi = vS
    vSs = vS
    if sliceStitch:
        _, vTi = vT
        _, vSi = vS
        vTs = "{}:{}".format(*vT)
        vSs = "{}:{}".format(*vS)

    tdslice = slicer.get(tdtrace, vTi, vti, sliceStitch=sliceStitch, sliceInfo=sliceInfo)
    logger.debugv("Combined tdslice:\n" + tdslice)
    sdslice = slicer.get(sdtrace, vSi, vsi, sliceStitch=sliceStitch, sliceInfo=sliceInfo)
    logger.debugv("Combined sdslice:\n" + sdslice)


    if sliceStitch:
        it, i = I[0]
    else:
        i = I[0]

    # memoryErrorPt = alignrst[0]

#     I = [alignrst[0]]
    # I = [errorInsn]


    SDFlow = pgv.AGraph(sdslice)
    TDFlow = pgv.AGraph(tdslice)

    print "Algo 2A"
    for V in getEdges(TDFlow, vTs):
        if sliceStitch:
            po = V[0]
            pt, p = po.split(":", 1)
            p = int(p)
            co = V[1]
            ct, c = co.split(":", 1)
            c = int(c)

            mem = V.attr["label"]
            passtru = False
            if mem.startswith("passtru"):  # passtru:805c800:1089664
                _, mem, forkins = mem.split(":", 2)
                passtru = True
        else:
            po = p = int(V[0])
            co = c = int(V[1])
            mem = V.attr["label"]

        if isRegister(mem): continue  # 7

        if sliceStitch:
            currentTraceHeader = ct
            curentInsn = c
            while not currentTraceHeader == it:
                currentTraceHeader, curentInsn = sliceInfo.getParent(currentTraceHeader)
                currentTraceHeader = sliceInfo.getName(currentTraceHeader)

            if i > curentInsn: continue  # 8  Skip due to line 8 or time ambiguity
        else:
            if i > c:  continue  # 8

        if isVPUsedToWriteV(tdtrace, c): continue  # 10

        vpp = getVPP(tdtrace, c)  # sliceStitch shouldnt need to join
        if vpp[0] in ["ESP", "EBP"]: continue  # Unable to determine vpp

        if sliceStitch:
            vpp[0] = (ct, vpp[0])

        logger.info("Possible edge: {} {} {}".format(po, co, mem))

        for vs in getEdges(SDFlow, vSs):
            logger.debug("proc SDFlow edge {} {}".format(vs, vs.attr["label"]))
            if sliceStitch:
                vspo = vs[0]
                vspt, vsp = vspo.split(":", 1)
                vsp = int(vsp)
                vsco = vs[1]
                vsct, vsc = vsco.split(":", 1)
                vsc = int(vsc)

                vsmem = vs.attr["label"]
                vspasstru = False
                if vsmem.startswith("passtru"):  # passtru:805c800:1089664
                    _, vsmem, forkins = vsmem.split(":", 2)
                    vspasstru = True
            else:
                vspo = vsp = int(vs[0])
                vsco = vsc = int(vs[1])
                vsmem = vs.attr["label"]

            if isRegister(vsmem): continue

            if sliceStitch:
                if not isAliveAt(tdtrace, (vspt, vsp), (ct, c), vsmem, sliceStitch=sliceStitch, sliceInfo=sliceInfo): continue
            else:
                if not isAliveAt(tdtrace, vsp, c, vsmem): continue

            print "VPP = {}, VP = {}, VP.addr = {},  VS = {}, VS.addr = {}".format(vpp, V, V.attr["label"], vs, vs.attr["label"])

            corruption_target = runAlgo1(sliceInfo.getTracePath(ct) if sliceStitch else tdtrace, I, vpp[0], sliceStitch=sliceStitch, sliceInfo=sliceInfo)

            if not corruption_target:
                print "single stitch candidates selection: faied to find"
            else:
                for l in corruption_target:
                    print "single stitch candidates selection: {edge}".format(edge=l)


    print "Algo 2B"
    for V in getEdges(SDFlow, vSs):
        if sliceStitch:
            po = V[0]
            pt, p = po.split(":", 1)
            p = int(p)
            co = V[1]
            ct, c = co.split(":", 1)
            c = int(c)

            mem = V.attr["label"]
            passtru = False
            if mem.startswith("passtru"):  # passtru:805c800:1089664
                _, mem, forkins = mem.split(":", 2)
                passtru = True
        else:
            po = p = int(V[0])
            co = c = int(V[1])
            mem = V.attr["label"]

        if isRegister(mem): continue  # 15

        # if p < min(I) :  continue  # 16

        if sliceStitch:
            currentTraceHeader = pt
            curentInsn = p
            while not currentTraceHeader == it:
                currentTraceHeader, curentInsn = sliceInfo.getParent(currentTraceHeader)
                currentTraceHeader = sliceInfo.getName(currentTraceHeader)

            if curentInsn < i: continue  # 16
        else:
            if p < i :  continue  # 16



        if not isVPUsedToWriteV(sdtrace, c): continue  # 18

        vpp = getVPP(tdtrace, c)
        if vpp[0] in ["ESP", "EBP"]: continue  # Unable to determine vpp

        if sliceStitch:
            vpp[0] = (pt, vpp[0])

        logger.info("Possible edge: {} {} {}".format(po, co, mem))
#
        # for vt in TDFlow.edges_iter():
        for vt in getEdges(TDFlow, vTs):
            logger.debug("proc TDFlow edge {} {}".format(vt, vt.attr["label"]))

            if sliceStitch:
                vtpo = vt[0]
                vtpt, vtp = vtpo.split(":", 1)
                vtp = int(vtp)
                vtco = vt[1]
                vtct, vtc = vtco.split(":", 1)
                vtc = int(vtc)

                vtmem = vt.attr["label"]
                vtpasstru = False
                if vtmem.startswith("passtru"):  # passtru:805c800:1089664
                    _, vtmem, forkins = vtmem.split(":", 2)
                    vtpasstru = True
            else:
                vtpo = vtp = int(vt[0])
                vtco = vtc = int(vt[1])
                vtmem = vt.attr["label"]


            if isRegister(vtmem): continue

            vt_time = vtp
            vprime_time = vtc

            if sliceStitch:
                logger.debug("{} < {} < {}".format(vtpo, co, vtco))
                if passtru:
                    if vtpt == ct:
                        if not (vt_time < c and c < forkins):continue
                    elif ct == vtct:
                        if not (c < vprime_time):continue  # 0 < c is assumed to be true
                    else:
                        continue  # Confirm skippable as the trace header is different thus not between 2 trace
                else:
                    if not (vtpt == ct and vt_time < c and c < vprime_time): continue
            else:
                logger.debug("{} < {} < {} : {}".format(vtpo, co, vtco, vt_time < c and c < vprime_time))
                if not (vt_time < c and c < vprime_time): continue

            print "VPP = {}, VP = {}, VP.addr = {}, VT = {} VT.addr = {}".format(vpp, V, V.attr["label"], vt, vt.attr["label"])

            corruption_target = runAlgo1(sliceInfo.getTracePath(ct) if sliceStitch else sdtrace, I, vpp[0], sliceStitch=sliceStitch, sliceInfo=sliceInfo)

            if not corruption_target:
                print "single stitch candidates selection: faied to find"
            else:
                for l in corruption_target:
                    print "single stitch candidates selection: {edge}".format(edge=l)
