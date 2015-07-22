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

    if vppRst == "err":
        logger.error("Unknown return: " + rst)
        raise Exception("Unknown return: " + rst)
    return vppRst

def runAlgo2():
    logger = logging.getLogger(__name__)

    benign_trace = "inpt/scalign-wuftpd-skiplib-7.bpt"
    benign_modload = "inpt/align-wuftpd-skiplib-7.bpt"
    error_trace = "inpt/scalign-err-wuftpd-skiplib-5.bpt"
    error_modload = "inpt/align-err-wuftpd-skiplib-5.bpt"

    tdtrace = benign_trace

    tdslice = "inpt/scalign-wuftpd-skiplib-7-1787632.dot"
    sdslice = "inpt/0-slice-1787598.dot"

    vT = 1787632
    vS = 1787598


    cp = 1123226
    alignrst = (1106195, 37863)

    tdgraph = tdslice
    sdgraph = sdslice
    src = vT
    memoryErrorPt = alignrst[0]




    SDFlow = pgv.AGraph(sdslice)
    TDFlow = pgv.AGraph(tdslice)

    visited = {}
    que = collections.deque()
    try:
        src_node = TDFlow.get_node(src)
    except KeyError:
        logger.warning("Source address %i not found in trace.", src)
        return []

    que.append(src_node)
    result = []
    while que:
        child = que.pop()

        if visited.get(child, False):
            continue

        visited[child] = True
        c = int(child.name)

        for parent_edge in TDFlow.in_edges_iter(child):
            parent = parent_edge[0]
            que.append(parent)

    #         if parent == child:
    #             continue

            mem = parent_edge.attr["label"]
            if isRegister(mem): continue  # 7

            p = int(parent.name)
            if memoryErrorPt > c:  continue  # 8

            if isVPUsedToWriteV(tdtrace, c): continue  # 10

            vpp = getVPP(tdtrace, c)

            logger.info("Possible edge: {} {} {}".format(p, c, mem))

            for vs in SDFlow.edges_iter():
                logger.debug("proc SDFlow edge {} {}".format(vs, vs.attr["label"]))
                if isRegister(vs.attr["label"]): continue
                if not isAliveAt(tdtrace, int(vs[0]), c, vs.attr["label"]): continue

                print "VPP = {}, VP = {},  VS = {} {}".format(vpp, parent_edge.attr["label"], vs, vs.attr["label"])

            #result.append([p, c, mem])
                # continue
def main():
    parser = argparse.ArgumentParser(description="")

#     parser.add_argument('-dcd', '--detect-critical-data', nargs="?", dest="bin_file" , help="Perform offline critical data detection.")
#     parser.add_argument("critical_data", help="File containing critical data info or funct.txt if -dct flag is used.")
#
#     parser.add_argument("trace_benign", help="Path to trace file (*.bpt).")
#     parser.add_argument("modload_benign", help="Output of gentrace.")
#
#     parser.add_argument("trace_error", help="Path to trace file (*.bpt).")
#     parser.add_argument("modload_error", help="Output of gentrace.")

    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
#     if not os.path.exists(args.critical_data):
#         parser.error("critical_data file do not exist");
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
    runAlgo2()

if __name__ == "__main__":
    main()


