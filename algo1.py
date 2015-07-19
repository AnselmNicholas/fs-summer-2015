import logging
import os
import enhanceLogging
from detCorruptTarget import findCorruptionTarget
from align import align
import argparse

def slice(trace_benign, insn, arch=32):
    """Perform the slice and return the result as a string.

    Executes the following command
        binslicer-{arch} {trace_benign} {insn}:0
    """
    logger = logging.getLogger(__name__)

    logger.info("Slicing %s at %s", trace_benign, insn)

    cmd = "binslicer-{arch} {trace_benign} {insn}:0".format(arch=arch, trace_benign=trace_benign, insn=insn)
    logger.debug("Executing command: " + cmd)

    with os.popen(cmd) as result:
        rst = result.read()
        logger.debugv("Result:\n%s", rst)

    return rst

def fetchMemoryError(trace_error, arch=32):
    """Run cp_detect and return result as a list of dict.

    Executes the following command
        cp_detect -{arch} {trace_error}

    Element in dict includes the following
        baseMemoryReg, indexMemoryReg, valueReg, insn, insnAddr
    """
    logger = logging.getLogger(__name__)

    logger.info("Detecting memory error of %s", trace_error)

    cmd = "cp_detect -{arch} {trace_error}".format(arch=arch, trace_error=trace_error)
    logger.debug("Executing command: " + cmd)

    ret = []
    currentVal = None
    with os.popen(cmd) as result:
        rst = result.read()
        logger.debugv("Result:\n%s", rst)

        for line in rst.splitlines():
            if line[:9] == "arbitrary":
                if currentVal is not None:
                    ret.append(currentVal)
                currentVal = {}
                continue

            line = line.split(":", 1)

            if line[0] == "\tbase memory reg":
                currentVal["baseMemoryReg"] = line[1]
            elif line[0] == '\tindex memory reg':
                currentVal["indexMemoryReg"] = line[1]
            elif line[0] == '\tvalue  reg':
                currentVal["valueReg"] = line[1]
            elif line[0] == "\tinsn":
                insn, addr = line[1].split()
                currentVal["insn"] = int(insn)
                currentVal["insnAddr"] = addr
            else:
                logger.warning("Unhandled cp_detect output: %s", line)

        ret.append(currentVal)

    return ret

def run():
    logger = logging.getLogger(__name__)
    alignRst = (1106175, 37863)
    criticalDataRst = {'seteuid': {
        '1000873': [['1000872', 'bfffdb80']],
        '1142250': [['1142249', 'bfffdf80']],
        '2469374': [['2469373', 'bfffdff0']],
        '2424795': [['2424794', 'bfffdf80']]
        }
    }

    inputFolder = "align/test1/"
    trace_benign = inputFolder + "scalign-wuftpd-skiplib-6.bpt"
    modload_benign = inputFolder + "align-wuftpd-skiplib-6.modload"
    trace_error = inputFolder + "scalign-err-wuftpd-skiplib-4.bpt"
    modload_error = inputFolder + "align-err-wuftpd-skiplib-4.modload"

    cp_detect_result = 1123206


    memory_error_vertex = fetchMemoryError(trace_error)

    ain_benign = align.genAIN(trace_benign, os.path.dirname(os.path.realpath(__file__)) + "/align/")
    ain_error = align.genAIN(trace_error, os.path.dirname(os.path.realpath(__file__)) + "/align/")
    processed_align = []

    slice_cache = {}

    memory_error_count = len(memory_error_vertex)
    for h, memory_error_insn in enumerate(memory_error_vertex, 1):
        logger.info("Processing memory error %i/%i", h, memory_error_count)
        alignRst = align.runAlign(ain_benign, modload_benign, ain_error, modload_error, memory_error_insn["insn"])

        if alignRst in processed_align:
            logger.info("Skipping - combination has already been processed")
            continue
        else:
            processed_align.append(alignRst)

        function_count = len(criticalDataRst.keys())
        for i, function_name in enumerate(criticalDataRst.keys(), 1):
            logger.info("Processing function %i/%i", i, function_count)

            function_call_count = len(criticalDataRst[function_name].keys())
            for j, call in enumerate(criticalDataRst[function_name].keys(), 1):
                logger.info("Processing %s call %i/%i", function_name , j, function_call_count)

                function_param_count = len(criticalDataRst[function_name][call])
                for k, param in enumerate(criticalDataRst[function_name][call], 1):
                    logger.info("Processing parameter %i/%i", k, function_param_count)

                    insn, espValue = param
                    slicedDFG = slice_cache.get((function_name, insn), None)

                    if slicedDFG is None:
                        slicedDFG = slice(trace_benign, insn)
                        slice_cache[(function_name, insn)] = slicedDFG

                    findCorruptionTarget.getCorruptionTargets(insn, alignRst[0], slicedDFG)

    os.unlink(ain_benign)
    os.unlink(ain_error)


def main():
    parser = argparse.ArgumentParser(description="")
#     parser.add_argument("functions", help="File containing a list of functions and their argument count. Stored in the format <function name> <paramcnt> \\n")
#     parser.add_argument("trace", help="Path to trace file (*.bpt).")
#     parser.add_argument("binary", help="Path to binary file.")
#     parser.add_argument('--gdb', dest='use_gdb', action='store_true', help="Use gdb instead of objdump")
    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
#     if not os.path.exists(args.functions):
#         parser.error("functions file do not exist");
#     if not os.path.exists(args.trace):
#         parser.error("trace file do not exist");
#     if not os.path.exists(args.binary):
#         parser.error("binary file do not exist");
    if args.verbose == 0:logging.basicConfig(level=logging.WARNING)
    elif args.verbose == 1: logging.basicConfig(level=logging.INFO)
    elif args.verbose == 2: logging.basicConfig(level=logging.DEBUG)
    else : logging.basicConfig(level=enhanceLogging.DEBUG_LEVELV_NUM)

    run()

if __name__ == "__main__":
    main()


