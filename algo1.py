import logging
import os
import enhanceLogging
from detCorruptTarget import findCorruptionTarget
import argparse

def slice(trace_benign, insn, arch=32):
    logger = logging.getLogger(__name__)

    logger.info("Slicing %s at %s", trace_benign, insn)

    cmd = "binslicer-{arch} {trace_benign} {insn}:0".format(arch=arch, trace_benign=trace_benign, insn=insn)
    logger.debug("Executing command: " + cmd)

    with os.popen(cmd) as result:
        rst = result.read()
        logger.debugv("Result:\n%s", rst)

    return rst

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
    error_benign = inputFolder + "scalign-err-wuftpd-skiplib-4.bpt"
    error_modload = inputFolder + "align-err-wuftpd-skiplib-4.modload"

    cp_detect_result = 1123206


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
                slicedDFG = slice(trace_benign, insn)
                findCorruptionTarget.getCorruptionTargets(insn, alignRst[0], slicedDFG)

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


