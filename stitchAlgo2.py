import logging
import os
import argparse
from stitchAlgo import runAlgo2
import enhanceLogging
from ConfigParser import SafeConfigParser, NoOptionError
from slicer import SliceInfo

def getOrDefault(function, input, defaults):
    try:
        return function(*input)
    except NoOptionError:
        return defaults

def main():

    def check_errorInsn(value):
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
        return ivalue
    parser = argparse.ArgumentParser(description="")



    subparsers = parser.add_subparsers(help='')
    base_subparser = argparse.ArgumentParser(add_help=False)
    base_subparser.add_argument('-v', '--verbose', action='count', default=0)


    parser_args = subparsers.add_parser("args", parents=[base_subparser])
    parser_args.set_defaults(which="args")

    parser_args.add_argument("benign_trace", help="Path to trace file (*.bpt).")
    parser_args.add_argument("vS", type=check_errorInsn, help="Instruction no vS")
    parser_args.add_argument("-vsi", type=check_errorInsn, help="index to slice on source insn (default = 0)", default=0)
    parser_args.add_argument("vT", type=check_errorInsn, help="Instruction no vT")
    parser_args.add_argument("-vti", type=check_errorInsn, help="index to slice on target insn (default = 0)", default=0)
    parser_args.add_argument("errorInsn", type=check_errorInsn, help="Instruction no of the memory error")


    parser_conf = subparsers.add_parser("run", parents=[base_subparser])
    parser_conf.set_defaults(which="run")
    parser_conf.add_argument("config", help="input file to run")

    args = parser.parse_args()
    if args.verbose == 0:logging.basicConfig(level=logging.WARNING)
    elif args.verbose == 1: logging.basicConfig(level=logging.INFO)
    elif args.verbose == 2: logging.basicConfig(level=logging.DEBUG)
    else : logging.basicConfig(level=enhanceLogging.DEBUG_LEVELV_NUM)

    logging.getLogger(__name__)
    logging.info("Logging level {0}".format(args.verbose))

    if (args.which == "args"):
        if not os.path.exists(args.benign_trace):
            parser.error("benign_trace do not exist");

        runAlgo2(args.benign_trace, [args.errorInsn], args.vS, args.vsi, args.vT, args.vti, -1)
    else:
        scp = SafeConfigParser()
        scp.read(args.config)

        localCache = scp.getboolean("misc", "cache")

        cp_aligned_insn = scp.getint("cp", "insn")
        cp_trace = getOrDefault(scp.get, ("cp", "trace"), "p")
        cp = [cp_aligned_insn, cp_trace]

        vs_insn = scp.getint("vs", "insn")
        vs_index = getOrDefault(scp.getint, ("vs", "index"), 0)
        vs_trace = getOrDefault(scp.get, ("vs", "trace"), "p")
        vs = [vs_insn, vs_index, vs_trace]

        vt_insn = scp.getint("vt", "insn")
        vt_index = getOrDefault(scp.getint, ("vt", "index"), 0)
        vt_trace = getOrDefault(scp.get, ("vt", "trace"), "p")
        vt = [vt_insn, vt_index, vt_trace]

        benign_trace_n = getOrDefault(scp.get, ("benign_trace", "name"), "")
        benign_trace_p = scp.get("benign_trace", "root_trace")
        benign_trace_c = [x for x in getOrDefault(scp.get, ("benign_trace", "child_trace"), "").split(",") if x]
        benign_trace_ml = getOrDefault(scp.get, ("benign_trace", "modload"), "")
        benign = SliceInfo(benign_trace_n, benign_trace_p, benign_trace_c, benign_trace_ml)

        # error_trace_n = getOrDefault(scp.get, ("error_trace", "name"), "")
        # error_trace_p = scp.get("error_trace", "root_trace")
        # error_trace_c = [x for x in getOrDefault(scp.get, ("error_trace", "child_trace"), "").split(",") if x]
        # error_trace_ml = getOrDefault(scp.get("error_trace", "modload"), "")
        # error = SliceInfo(error_trace_n, error_trace_p, error_trace_c, error_trace_ml)

        sliceStitch = False
        if benign.canStitchSlice():
            sliceStitch = True

        if sliceStitch:
            runAlgo2(benign.getTrace(vt[2]), [(benign.getNameK(cp[1]), cp[0])], (benign.getNameK(vs[2]), vs[0]), vs[1], (benign.getNameK(vt[2]), vt[0]), vt[1], -1, benign.getTrace(vs[2]), sliceStitch, sliceInfo=benign)
        else:
            runAlgo2(benign.getTrace(vt[2]), [cp[0]], vs[0], vs[1], vt[0], vt[1], -1)


if __name__ == "__main__":
    main()


