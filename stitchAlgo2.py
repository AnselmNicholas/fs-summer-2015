import logging
import os
import argparse
from stitchAlgo import runAlgo2
import enhanceLogging

def main():

    def check_errorInsn(value):
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
        return ivalue
    parser = argparse.ArgumentParser(description="")

    parser.add_argument("benign_trace", help="Path to trace file (*.bpt).")
    parser.add_argument("vS", type=check_errorInsn, help="Instruction no vS")
    parser.add_argument("-vsi", type=check_errorInsn, help="index to slice on source insn (default = 0)", default=0)
    parser.add_argument("vT", type=check_errorInsn, help="Instruction no vT")
    parser.add_argument("-vti", type=check_errorInsn, help="index to slice on target insn (default = 0)", default=0)
    parser.add_argument("errorInsn", type=check_errorInsn, help="Instruction no of the memory error")

    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
    if not os.path.exists(args.benign_trace):
        parser.error("benign_trace do not exist");

    if args.verbose == 0:logging.basicConfig(level=logging.WARNING)
    elif args.verbose == 1: logging.basicConfig(level=logging.INFO)
    elif args.verbose == 2: logging.basicConfig(level=logging.DEBUG)
    else : logging.basicConfig(level=enhanceLogging.DEBUG_LEVELV_NUM)


    runAlgo2(args.benign_trace, [args.errorInsn], args.vS, args.vsi, args.vT, args.vti, -1)

if __name__ == "__main__":
    main()


