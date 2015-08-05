from __future__ import absolute_import

import pygraphviz as pgv
import collections
import argparse
import os
import logging
import slicer
from stitchAlgo import runAlgo1

# def getCorruptionTargets(src, target, graph):
# #     dfg = pgv.AGraph("2424794.dot")
# #     src = 2424794
# #     target = 1106175
#     logger = logging.getLogger(__name__)
#     logger.info("Determining corruption target for src {0} target {1}.".format(src, target))
#
#     dfg = pgv.AGraph(graph)
#
#     visited = {}
#     que = collections.deque()
#     try:
#         src_node = dfg.get_node(src)
#     except KeyError:
#         logger.warning("Source address %i not found in trace.", src)
#         return []
#     que.append(src_node)
#     result = []
#     while que:
#         child = que.pop()
#
#         if visited.get(child, False):
#             continue
#
#         visited[child] = True
#         c = int(child.name)
#
#         for parent_edge in dfg.in_edges_iter(child):
#             parent = parent_edge[0]
#
#             if parent == child:
#                 continue
#
#             p = int(parent.name)
#
#             if p < target and target < c:
#                 mem = parent_edge.attr["label"]
#                 logger.info("Possible edge: {} {} {}".format(p, c, mem))
#
#                 result.append([p, c, mem])
#                 continue
#
#             que.append(parent)
#
#     return result
# 
# def runAlgo1(src, target, G):
#     """
#     
#     Input:
#         G = benign trace
#         src = vT
#         target = I 
#     
#     """
#     from algo2.algo2 import getEdges, isRegister
# 
#     logger = logging.getLogger(__name__)
#     logger.info("Determining corruption target for src {0} target {1}.".format(src, target))
# 
#     result = []
# 
#     vT = src
#     I = [target]
# 
#     tdslice = slicer.get(G, vT)
# 
#     TDFlow = pgv.AGraph(tdslice)
# 
#     for V in getEdges(TDFlow, vT):
#         p = int(V[0])
#         c = int(V[1])
# 
#         mem = V.attr["label"]
#         if isRegister(mem): continue  # 4
# 
#         if p < I[0] and I[0] < c:
#             logger.info("Possible edge: {} {} {}".format(p, c, mem))
#             result.append([p, c, mem])
# 
#     return result


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

    if args.verbose == 1: logging.basicConfig(level=logging.INFO)
    if args.verbose > 1: logging.basicConfig(level=logging.DEBUG)

    run(args.criticalDataInsn, args.errorFunctionInsn, args.benign_trace)

if __name__ == "__main__":
    main()
    # getCorruptionTargets(1, 1, )
