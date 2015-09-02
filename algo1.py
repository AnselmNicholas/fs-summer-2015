import logging
import os
import align
from criticalDataIdentify import critDataIdentify
import argparse
import json
from stitchAlgo import runAlgo1
import enhanceLogging
from misc import execute
from ConfigParser import SafeConfigParser
from ConfigParser import NoOptionError
from slicer import SliceInfo
import misc, string

def fetchMemoryError(trace_error, arch=32, cache=False):
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

    rst = execute(cmd, cache)

    rst = misc.Lookahead(rst.splitlines())

    for line in rst:
        logger.debugv(line)
        if line[:9] == "arbitrary":
            currentVal = {"mode":"arbitrary", "arbitrary":line[10:][:-2]}  # -2 to remove ":\n"
            while rst.lookahead() is not None and rst.lookahead()[0] == "\t":
                line = rst.next()
                logger.debugv(line)

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
        elif line[:5] == "Found":
            currentVal = {"mode":"Found", "mesage":line, "insnWrite":[]}
            while rst.lookahead() is not None and rst.lookahead()[0] in string.digits:
                logger.debugv(rst.lookahead())
                insn, addr = rst.next().split()
                insn = int(insn)

                currentVal["insnWrite"].append((insn, addr))

                currentVal["insn"] = insn
                currentVal["insnAddr"] = addr
        else:
            logger.warning("Unhandled cp_detect output: %s", line)

        ret.append(currentVal)

    return ret

def execAlgo1(criticalDataRst, trace_benign, modload_benign, trace_error, modload_error, identifyCriticalData=False, functions_file="", binary_file=""):
    logger = logging.getLogger(__name__)

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

def run2(cp_traceIn, alignIn, criticalIn, benignIn, errorIn, cache=False):
    """
    cp_trace = scp.get("cp", "trace")
    align = [align_b, align_e]
    critical = [critical_data_functions, critical_data_trace, critical_data_binary_file]
    benign = sliceInfo
    error = sliceInfo
    """

    logger = logging.getLogger(__name__)

    sliceStitch = False
    if benignIn.canStitchSlice():
        sliceStitch = True

    criticalDataRst = critDataIdentify.run(criticalIn[0], benignIn.getTrace(criticalIn[1]), criticalIn[2])

    for i, function_name in enumerate(criticalDataRst.keys(), 1):
        for j, call in enumerate(criticalDataRst[function_name].keys(), 1):
            for k, param in enumerate(criticalDataRst[function_name][call], 1):
                print "critical data detection: found {} {} {} @ {}".format(function_name, j, call, param)

    memory_error_vertex = fetchMemoryError(errorIn.getTrace(cp_traceIn))
    for i in memory_error_vertex:
        print "cp_detection: found error @ {0}".format(i["insn"])

    ain_benign = align.genAIN(benignIn.getTrace(alignIn[0]))
    ain_error = align.genAIN(errorIn.getTrace(alignIn[1]))
    processed_align = []

    memory_error_count = len(memory_error_vertex)
    for h, memory_error_insn in enumerate(memory_error_vertex, 1):
        logger.info("Processing memory error %i/%i", h, memory_error_count)
        alignRst = align.runAlign(ain_benign, benignIn.ml, ain_error, errorIn.ml, memory_error_insn["insn"])

        if alignRst[0] == align.invalidOffset:
            logger.info("Skipping - unable to determine corresponding instruction in benign trace")
            continue

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

                    if sliceStitch:
                        corruption_target = runAlgo1(benignIn.getTrace(criticalIn[1]), [(benignIn.getNameK(alignIn[0]), alignRst[0])], (benignIn.getNameK(criticalIn[1]), insn), sliceStitch=True, sliceInfo=benignIn)
                    else:
                        corruption_target = runAlgo1(benignIn.getTrace(criticalIn[1]), [alignRst[0]], insn, sliceStitch=False, sliceInfo=benignIn)

                    if not corruption_target:
                        print "single stitch candidates selection: {function_name} {call_no} {param_no}: faied to find".format(function_name=function_name, call_no=j, param_no=k)
                    else:
                        for l in corruption_target:
                            print "single stitch candidates selection: {function_name} {call_no} {param_no}: {edge}".format(function_name=function_name, call_no=j, param_no=k, edge=l)

    os.unlink(ain_benign)
    os.unlink(ain_error)

def getOrDefault(function, input, defaults):
    try:
        return function(*input)
    except NoOptionError:
        return defaults

def main():
    parser = argparse.ArgumentParser(description="")

    subparsers = parser.add_subparsers(help='')
    base_subparser = argparse.ArgumentParser(add_help=False)
    base_subparser.add_argument('-v', '--verbose', action='count', default=0)


    parser_args = subparsers.add_parser("args", parents=[base_subparser])
    parser_args.set_defaults(which="args")

    parser_args.add_argument('-dcd', '--detect-critical-data', nargs="?", dest="bin_file" , help="Perform offline critical data detection.")
    parser_args.add_argument("critical_data", help="File containing critical data info or funct.txt if -dct flag is used.")

    parser_args.add_argument("trace_benign", help="Path to trace file (*.bpt).")
    parser_args.add_argument("modload_benign", help="Output of gentrace.")

    parser_args.add_argument("trace_error", help="Path to trace file (*.bpt).")
    parser_args.add_argument("modload_error", help="Output of gentrace.")


    parser_conf = subparsers.add_parser("run", parents=[base_subparser])
    parser_conf.set_defaults(which="run")
    parser_conf.add_argument("config", help="input file to run")


    args = parser.parse_args()
    if args.verbose == 0:logging.basicConfig(level=logging.WARNING)
    elif args.verbose == 1: logging.basicConfig(level=logging.INFO)
    elif args.verbose == 2: logging.basicConfig(level=logging.DEBUG)
    else : logging.basicConfig(level=enhanceLogging.DEBUG_LEVELV_NUM)

    if (args.which == "args"):
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
        if not args.bin_file is None:
            if not os.path.exists(args.bin_file):
                parser.error("bin file do not exist");

        run(args.critical_data, args.trace_benign, args.modload_benign, args.trace_error, args.modload_error, binary_file=args.bin_file)
    else:
        scp = SafeConfigParser()
        scp.read(args.config)

        localCache = scp.getboolean("misc", "cache")

        align_b = scp.get("align", "benign")
        align_e = scp.get("align", "error")
        align = [align_b, align_e]

        cp_trace = scp.get("cp", "trace")

        critical_data_functions = scp.get("criticalDataIdentify", "functions")
        critical_data_trace = scp.get("criticalDataIdentify", "trace")
        critical_data_binary_file = scp.get("criticalDataIdentify", "binary")
        critical = [critical_data_functions, critical_data_trace, critical_data_binary_file]

        benign_trace_n = getOrDefault(scp.get, ("benign_trace", "name"), "")
        benign_trace_p = scp.get("benign_trace", "root_trace")
        benign_trace_c = [x.strip() for x in getOrDefault(scp.get, ("benign_trace", "child_trace"), "").split(",") if x]
        benign_trace_ml = getOrDefault(scp.get, ("benign_trace", "modload"), "")
        benign = SliceInfo(benign_trace_n, benign_trace_p, benign_trace_c, benign_trace_ml)

        error_trace_n = getOrDefault(scp.get, ("error_trace", "name"), "")
        error_trace_p = scp.get("error_trace", "root_trace")
        error_trace_c = [x.strip() for x in getOrDefault(scp.get, ("error_trace", "child_trace"), "").split(",") if x]
        error_trace_ml = getOrDefault(scp.get, ("error_trace", "modload"), "")
        error = SliceInfo(error_trace_n, error_trace_p, error_trace_c, error_trace_ml)

        run2(cp_trace, align, critical, benign, error, cache=localCache)

if __name__ == "__main__":
    main()


