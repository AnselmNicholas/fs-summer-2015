import argparse
import os
import logging
from stitchAlgo import runAlgo1
import enhanceLogging

def run(criticalDataInsn, errorFunctionInsn, benign_trace):
    runAlgo1(benign_trace,[errorFunctionInsn], criticalDataInsn)

def main():
    def check_errorInsn(value):
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
        return ivalue

    parser = argparse.ArgumentParser(description="Search for corruption target")
    parser.add_argument("criticalDataInsn", type=check_errorInsn, help="Insn of critical data.")
    parser.add_argument("errorFunctionInsn", type=check_errorInsn, help="Insn of function that contain error in benign trace.")
    parser.add_argument("benign_trace", help="Slice of trace with criticalDataInsn as the final node.")
    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
    if not os.path.exists(args.benign_trace):
        parser.error("functions file do not exist");

    if args.verbose == 0:logging.basicConfig(level=logging.WARNING)
    elif args.verbose == 1: logging.basicConfig(level=logging.INFO)
    elif args.verbose == 2: logging.basicConfig(level=logging.DEBUG)
    else : logging.basicConfig(level=enhanceLogging.DEBUG_LEVELV_NUM)

    run(args.criticalDataInsn, args.errorFunctionInsn, args.benign_trace)

if __name__ == "__main__":
    main()
    # getCorruptionTargets(1, 1, )
