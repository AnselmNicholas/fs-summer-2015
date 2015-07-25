import logging
import pygraphviz as pgv
import collections
import os
import subprocess
import argparse

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

def getEdges(graph,src,):
    logger = logging.getLogger(__name__)
    #src = vS
    visited = {}
    que = collections.deque()
    try:
        src_node = graph.get_node(src)
    except KeyError:
        logger.error("Source address %i not found in trace.", src)
        raise Exception("Source address %i not found in trace.", src)


    que.append(src_node)
    result = []
    while que:
        child = que.pop()

        if visited.get(child, False):
            continue

        visited[child] = True
        c = int(child.name)

        for parent_edge in graph.in_edges_iter(child):
            parent = parent_edge[0]
            que.append(parent)

    #         if parent == child:
    #             continue
            
            yield parent_edge
#             mem = parent_edge.attr["label"]
#             if isRegister(mem): continue  # 15
# 
#             p = int(parent.name)
#             if p < min(I) :  continue  # 16



def runAlgo2(benign_trace, tdslice, sdslice, vT, vS, errorInsn):
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

    tdtrace = benign_trace
    sdtrace = benign_trace

    tdgraph = tdslice
    sdgraph = sdslice

    # memoryErrorPt = alignrst[0]

#     I = [alignrst[0]]
    I = [errorInsn]


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
        
        logger.info("Possible edge: {} {} {}".format(p, c, mem))
        
        for vs in getEdges(SDFlow, vS):
            logger.debug("proc SDFlow edge {} {}".format(vs, vs.attr["label"]))
            if isRegister(vs.attr["label"]): continue
            if not isAliveAt(tdtrace, int(vs[0]), c, vs.attr["label"]): continue
        
            print "VPP = {}, VP = {},  VS = {} {}".format(vpp, V.attr["label"], vs, vs.attr["label"])

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
        #for vt in TDFlow.edges_iter():
        for vt in getEdges(TDFlow, vT):
            logger.debug("proc TDFlow edge {} {}".format(vt, vt.attr["label"]))
            if isRegister(vt.attr["label"]): continue

            vt_time = int(vt[0])
            vprime_time = int(vt[1])
            if not (vt_time < c and c < vprime_time): continue

            print "VPP = {}, VP = {},  VT = {} {}".format(vpp, V.attr["label"], vt, vt.attr["label"])
            # result.append([p, c, mem])
                # continue
def main():

    def check_errorInsn(value):
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
        return ivalue
    parser = argparse.ArgumentParser(description="")

#     parser.add_argument('-dcd', '--detect-critical-data', nargs="?", dest="bin_file" , help="Perform offline critical data detection.")
#     parser.add_argument("critical_data", help="File containing critical data info or funct.txt if -dct flag is used.")
#
    parser.add_argument("benign_trace", help="Path to trace file (*.bpt).")
    parser.add_argument("tdslice", help="Path to slice file (*.dot).")
    parser.add_argument("sdslice", help="Path to slice file (*.dot).")
    parser.add_argument("vT", type=check_errorInsn, help="Instruction no vT")
    parser.add_argument("vS", type=check_errorInsn, help="Instruction no vS")
    parser.add_argument("errorInsn", type=check_errorInsn, help="Instruction no of the memory error")
#     parser.add_argument("modload_benign", help="Output of gentrace.")
#
#     parser.add_argument("trace_error", help="Path to trace file (*.bpt).")
#     parser.add_argument("modload_error", help="Output of gentrace.")

    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
    if not os.path.exists(args.benign_trace):
        parser.error("benign_trace do not exist");
    if not os.path.exists(args.tdslice):
        parser.error("tdslice do not exist");
    if not os.path.exists(args.sdslice):
        parser.error("sdslice do not exist");
#     if not os.path.exists(args.trace_benign):
#         parser.error("trace file do not exist");
#     if not os.path.exists(args.modload_benign):
#         parser.error("modload file do not exist");
#     if not os.path.exists(args.trace_error):
#         parser.error("trace file do not exist");
#     if not os.path.exists(args.modload_error):
#         parser.error("modload file do not exist");

    if args.verbose == 0:logging.basicConfig(level=logging.WARNING)
    elif args.verbose == 1: logging.basicConfig(level=logging.INFO)
    elif args.verbose == 2: logging.basicConfig(level=logging.DEBUG)
#     else : logging.basicConfig(level=enhanceLogging.DEBUG_LEVELV_NUM)

#     run(args.critical_data, args.trace_benign, args.modload_benign, args.trace_error, args.modload_error, binary_file=args.bin_file)
    runAlgo2(args.benign_trace, args.tdslice, args.sdslice, args.vT, args.vS, args.errorInsn)
#     runAlgo2()

if __name__ == "__main__":
    main()


