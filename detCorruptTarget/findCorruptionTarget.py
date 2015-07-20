from __future__ import absolute_import

import pygraphviz as pgv
import collections
import argparse
import os
import logging


def getCorruptionTargets(src, target, graph):
#     dfg = pgv.AGraph("2424794.dot")
#     src = 2424794
#     target = 1106175
    logger = logging.getLogger(__name__)
    logger.info("Determining corruption target for src {0} target {1}.".format(src, target))

    dfg = pgv.AGraph(graph)

    visited = {}
    que = collections.deque()
    try:
        src_node = dfg.get_node(src)
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

        for parent_edge in dfg.in_edges_iter(child):
            parent = parent_edge[0]

            if parent == child:
                continue

            p = int(parent.name)

            if p < target and target < c:
                mem = parent_edge.attr["label"]
                logger.info("Possible edge: {} {} {}".format(p, c, mem))

                result.append([p, c, mem])
                continue

            que.append(parent)

    return result

def run(criticalDataInsn, errorFunctionInsn, dfgSlice):
    getCorruptionTargets(criticalDataInsn, errorFunctionInsn, dfgSlice)

def main():
    def check_errorInsn(value):
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
        return ivalue

    parser = argparse.ArgumentParser(description="Search for corruption target")
    parser.add_argument("criticalDataInsn", type=check_errorInsn, help="Insn of critical data.")
    parser.add_argument("errorFunctionInsn", type=check_errorInsn, help="Insn of function that contain error in benign trace.")
    parser.add_argument("dfgSlice", help="Slice of trace with criticalDataInsn as the final node.")
    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
    if not os.path.exists(args.dfgSlice):
        parser.error("functions file do not exist");

    if args.verbose == 1: logging.basicConfig(level=logging.INFO)
    if args.verbose > 1: logging.basicConfig(level=logging.DEBUG)

    run(args.criticalDataInsn, args.errorFunctionInsn, args.dfgSlice)

if __name__ == "__main__":
    main()
    # getCorruptionTargets(1, 1, )
