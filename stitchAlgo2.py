import logging
import os
import argparse
from stitchAlgo import runAlgo2
import enhanceLogging
from ConfigParser import SafeConfigParser

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
        vS = scp.getint("common", "vs")
        vsi = scp.getint("common", "vsi")
        vT = scp.getint("common", "vt")
        vti = scp.getint("common", "vti")
        cp = scp.getint("common", "cp")
        
        benign_trace = scp.get("benign_trace","root_trace")
        
        runAlgo2(benign_trace, [cp], vS, vsi, vT, vti, -1)


if __name__ == "__main__":
    main()


