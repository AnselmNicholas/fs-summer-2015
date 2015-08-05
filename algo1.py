import logging
import os
from align import align
from criticalDataIdentify import critDataIdentify
import argparse
import json
import subprocess
from stitchAlgo import runAlgo1
import enhanceLogging

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
#     stdout, stdin, stderr = os.popen3(cmd)

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)

    stdout = p.stdout
    stderr = p.stderr
    with stdout as result:
        with stderr as err:
            errTxt = err.read()
            if errTxt:
                logger.error("Error in command:\n" + errTxt)
                raise Exception("Error executing command: " + cmd)

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

def execAlgo1(criticalDataRst, trace_benign, modload_benign, trace_error, modload_error, identifyCriticalData=False, functions_file="", binary_file=""):
    logger = logging.getLogger(__name__)
#     criticalDataRst = {'seteuid': {
#         '1000873': [['1000872', 'bfffdb80']],
#         '1142250': [['1142249', 'bfffdf80']],
#         '2469374': [['2469373', 'bfffdff0']],
#         '2424795': [['2424794', 'bfffdf80']]
#         }
#     }
#
#     inputFolder = "align/test1/"
#     trace_benign = inputFolder + "scalign-wuftpd-skiplib-6.bpt"
#     modload_benign = inputFolder + "align-wuftpd-skiplib-6.modload"
#     trace_error = inputFolder + "scalign-err-wuftpd-skiplib-4.bpt"
#     modload_error = inputFolder + "align-err-wuftpd-skiplib-4.modload"

    if (identifyCriticalData):
        criticalDataRst = critDataIdentify.run(functions_file, trace_benign, binary_file)

    for i, function_name in enumerate(criticalDataRst.keys(), 1):
        for j, call in enumerate(criticalDataRst[function_name].keys(), 1):
            for k, param in enumerate(criticalDataRst[function_name][call], 1):
                print "critical data detection: found {} {} {} @ {}".format(function_name, j, call, param)

    memory_error_vertex = fetchMemoryError(trace_error)
    for i in memory_error_vertex:
        print "cp_detection: found error @ {0}".format(i["insn"])


    ain_benign = align.genAIN(trace_benign)
    ain_error = align.genAIN(trace_error)
    processed_align = []

    memory_error_count = len(memory_error_vertex)
    for h, memory_error_insn in enumerate(memory_error_vertex, 1):
        logger.info("Processing memory error %i/%i", h, memory_error_count)
        alignRst = align.runAlign(ain_benign, modload_benign, ain_error, modload_error, memory_error_insn["insn"])

        if alignRst in processed_align:
            logger.info("Skipping - combination has already been processed")
            continue
        else:
            processed_align.append(alignRst)
            print "aligning: {0} aligned to {1}".format(memory_error_insn["insn"], alignRst)

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

                    corruption_target = runAlgo1(trace_benign, [alignRst[0]], insn)

                    if not corruption_target:
                        print "single stitch candidates selection: {function_name} {call_no} {param_no}: faied to find".format(function_name=function_name, call_no=j, param_no=k)
                    else:
                        for l in corruption_target:
                            print "single stitch candidates selection: {function_name} {call_no} {param_no}: {edge}".format(function_name=function_name, call_no=j, param_no=k, edge=l)

    os.unlink(ain_benign)
    os.unlink(ain_error)

def run(criticalDataFileOrFunctFile, trace_benign, modload_benign, trace_error, modload_error, binary_file=""):
    if (binary_file):
        execAlgo1("", trace_benign, modload_benign, trace_error, modload_error, identifyCriticalData=True, functions_file=criticalDataFileOrFunctFile, binary_file=binary_file)
    else:
        with open(criticalDataFileOrFunctFile) as f:
            criticalDataRst = json.load(f)
            execAlgo1(criticalDataRst, trace_benign, modload_benign, trace_error, modload_error)

def main():
    parser = argparse.ArgumentParser(description="")

    parser.add_argument('-dcd', '--detect-critical-data', nargs="?", dest="bin_file" , help="Perform offline critical data detection.")
    parser.add_argument("critical_data", help="File containing critical data info or funct.txt if -dct flag is used.")

    parser.add_argument("trace_benign", help="Path to trace file (*.bpt).")
    parser.add_argument("modload_benign", help="Output of gentrace.")

    parser.add_argument("trace_error", help="Path to trace file (*.bpt).")
    parser.add_argument("modload_error", help="Output of gentrace.")

    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
    if not os.path.exists(args.critical_data):
        parser.error("critical_data file do not exist");
    if not os.path.exists(args.trace_benign):
        parser.error("trace file do not exist");
    if not os.path.exists(args.modload_benign):
        parser.error("modload file do not exist");
    if not os.path.exists(args.trace_error):
        parser.error("trace file do not exist");
    if not os.path.exists(args.modload_error):
        parser.error("modload file do not exist");

    if args.verbose == 0:logging.basicConfig(level=logging.WARNING)
    elif args.verbose == 1: logging.basicConfig(level=logging.INFO)
    elif args.verbose == 2: logging.basicConfig(level=logging.DEBUG)
    else : logging.basicConfig(level=enhanceLogging.DEBUG_LEVELV_NUM)

    run(args.critical_data, args.trace_benign, args.modload_benign, args.trace_error, args.modload_error, binary_file=args.bin_file)

if __name__ == "__main__":
    main()


