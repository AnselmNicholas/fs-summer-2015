import re
import numpy as np
import logging
import sys
import os
from tempfile import mkstemp
import cmd

class Lookahead:
    """Lookahead iterator for efficient parsing

    http://stackoverflow.com/a/1517965/1364256
    """
    def __init__(self, itera):
        self.iter = iter(itera)
        self.buffer = []

    def __iter__(self):
        return self

    def next(self):
        if self.buffer:
            return self.buffer.pop(0)
        else:
            return self.iter.next()

    def lookahead(self, n=0):
        """Return an item n entries ahead in the iteration."""
        while n >= len(self.buffer):
            try:
                self.buffer.append(self.iter.next())
            except StopIteration:
                return None
        return self.buffer[n]

def butlast(xs):
    xs = iter(xs)
    prev = xs.next()
    for x in xs:
        yield prev
        prev = x

def runAnalysis(aiesp, modload, lmin=-1, lmax=-1, recursionLimit=10000000, visualize=0, simplified=1, chain=False):
    logger = logging.getLogger(__name__)
    sys.setrecursionlimit(recursionLimit)

    logger.info("Recursion limit set to {0}".format(recursionLimit))
    logger.info("aiesp file is {0}".format(aiesp))
    logger.info("modload file is {0}".format(modload))
    logger.info("lmin {0} lmax {1} visualize {2} simplified {3} chain {4}".format(lmin, lmax, visualize, simplified, chain))

#     testInput = [("scwuftpd-skiplib.aiesp", "scwuftpd-skiplib.modload"),  # 0
#                  ("3150-out-noskip.aiesp", "bof1-maps", 90898, 93780),  # 90897, 91589),  # 0x804856b, 0x8048588
#                  ("3577-bof2-noskip.aiesp", "bof2-maps"),  # 2
#                  ("3564-bof2-skip.aiesp", "bof2-maps"),
#                  ("5802-readme.aiesp", ""),  # [91219:91912]
#                  ("3150-out-noskip.aiesp", "bof1-maps"),  # 5
#                  ("foo.aiesp", "foo-maps", 90812, 91549),  # 6
#                  ("foo2.aiesp", "foo2-maps", 90812, 162730),
#                  ("foo2-mltest.aiesp", "foo2-mltest-modload", 90812, 162730),  # 8
#                  ("scwuftpd-skiplib-p2.aiesp", "scwuftpd-skiplib-p2.modload"),
#                  ("scwuftpd-skiplib-p3.aiesp", "scwuftpd-skiplib-p3.modload"),
#                  ("scwuftpd-skiplib-p4.aiesp", "scwuftpd-skiplib-p4.modload")
#                  ]
#     testChoice = -1
#     testInput = testInput[testChoice]


    testInput = (aiesp, modload)

    # # Init Lic

    functionStack = []
    currentInstructionList = []  # Current function
    currentInstrCount = 0
    currentFunctionCallCnt = 0
    currentFunctionContainUnresolvedRet = 0


    functionInfo = {}
    totalCallCnt = totalRetCnt = 0
    inputFile = testInput[0]

    lmin -= 1
    lmax -= 1

    logger.info("Begin processing aiesp file")
    with open(inputFile) as f:
        inpt = Lookahead(f)

        for idx, line in enumerate(inpt):
            if lmin > 0:
                if idx < lmin: continue
            if lmax > 0:
                if idx > lmax: break

            line = line.strip()

            line_input = re.split("\W+", line, 2)
            address = line_input[0]
            operand = line_input[1]
            remainder = line_input[2] if len(line_input) > 2 else None

            try:
                if operand == "calll":
                    target, espValue = remainder.split()

                    if not target.startswith("0x") or target[-1] == (")"):  # handle indirect totalCallCnt
                        target = inpt.lookahead().split()[0]

                    # print "totalCallCnt {}".format(espValue)
                    currentInstructionList.append(line)
                    currentInstrCount += 1
                    currentFunctionCallCnt += 1
                    functionStack.append([espValue, currentInstructionList, currentInstrCount, target, currentFunctionContainUnresolvedRet])
                    currentInstructionList = []
                    currentInstrCount = 0
                    currentFunctionCallCnt = 0
                    currentFunctionContainUnresolvedRet = 0

                    # functionInfo[target] =
                    d = functionInfo.get(target, {"callCount" :0, "instructionCount" : [], "unresolvedRet":[]})
                    d["callCount"] += 1
                    functionInfo[target] = d

                    # print "{:<10} {} {} {}".format(address, header, operand, espValue)
                    # display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, espValue))
                    # header += ":"

                    totalCallCnt += 1
                elif operand == "retl":

                    remainder = remainder.split()
                    if len(remainder) == 1:
                        espValue = '%x' % (int(remainder[0], 16) + 4)  # hex(int(remainder[0], 16) + 4)[2:-1]
                    else:
                        espValue = '%x' % (int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)  # hex(int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)[2:-1]


                    if len(functionStack) == 0 or not functionStack[-1][0] == espValue:  # Unable to return
                        currentInstructionList.append(line)
                        currentInstrCount += 1
                        currentFunctionContainUnresolvedRet = 1

                    else:
                        currentInstructionList.append(line)
                        currentInstrCount += 1
                        rst = functionStack.pop()

                        functionInfo[rst[3]]["instructionCount"].append(currentInstrCount)
                        functionInfo[rst[3]]["unresolvedRet"].append(currentFunctionContainUnresolvedRet)

                        t = rst[1]
                        t.append(currentInstructionList)
                        currentInstructionList = t
                        currentInstrCount += rst[2]
                        if not currentFunctionContainUnresolvedRet:
                            currentFunctionContainUnresolvedRet = rst[4]



                        # print "{:<10} {} {} {}".format(address, header, operand, espValue)
                        # display.write("<li class='lastChild'>{:<10} {} {} {}</li></ul></li>".format(address, header, operand, espValue))
                        # header = header[:-1]


                        # print "{:<10} {} {} {} \t\t\t\t Err".format(address, header, operand, espValue)
                        # display.write("<li>{:<10} {} {} {} \t\t\t\t Err</li>".format(address, header, operand, espValue))



                    # print "totalRetCnt {}".format(espValue)

                    totalRetCnt += 1
                    # functionStack.pop()
                else:

                    currentInstructionList.append(line)
                    currentInstrCount += 1
                    # print "{:<10} {} {} {}".format(address, header, operand, remainder)

                    # display.write("<li>{:<10} {} {} {}</li>".format(address, header, operand, remainder))
                    pass

            except IndexError, e:
                print idx, e, line
                # break


        while len(functionStack):
            rst = functionStack.pop()

            functionInfo[rst[3]]["instructionCount"].append(currentInstrCount)
            functionInfo[rst[3]]["unresolvedRet"].append(currentFunctionContainUnresolvedRet)

            t = rst[1]
            t.append(currentInstructionList)
            currentInstructionList = t
            currentInstrCount += rst[2]
            if not currentFunctionContainUnresolvedRet:
                currentFunctionContainUnresolvedRet = rst[4]


    logger.info("aiesp processed")
    # Processing





    def processList(xs, header="", debug=False):
        global totalCallCnt
        global totalRetCnt
        for x in butlast(xs):
            if type(x) == list:
                processList(x, header + ":")
            else:
                line_input = re.split("\W+", x, 2)
                address = line_input[0]
                operand = line_input[1]
                remainder = line_input[2] if len(line_input) > 2 else None

                if operand == "calll":

                    espValue = remainder.split()[-1]
                    # print "totalCallCnt {}".format(espValue)

                    if debug: print "{:<10} {} {} {}".format(address, header, operand, remainder)
                    display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, remainder))
                    # header += ":"


                elif operand == "retl":

                    remainder = remainder.split()
                    if len(remainder) == 1:
                        espValue = '%x' % (int(remainder[0], 16) + 4)  # hex(int(remainder[0], 16) + 4)[2:-1]

                    else:
                        espValue = '%x' % (int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)  # hex(int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)[2:-1]





                    if debug: print "{:<10} {} {} {} \t\t\t\t Err".format(address, header, operand, espValue)
                    display.write("<li><font color='red'>{:<10} {} {} {} \t\t\t\t Err</font></li>".format(address, header, operand, espValue))



                    # print "totalRetCnt {}".format(espValue)



                else:


                    if debug: print "{:<10} {} {} {}".format(address, header, operand, remainder)

                    display.write("<li>{:<10} {} {} {}</li>".format(address, header, operand, remainder))


        if type(xs[-1]) == list:
            processList(xs[-1], header + ":")
        else:

            line_input = re.split("\W+", xs[-1], 2)
            address = line_input[0]
            operand = line_input[1]
            remainder = line_input[2] if len(line_input) > 2 else None

            if operand == "calll":

    #             espValue = remainder.split()[-1]
    #             # print "totalCallCnt {}".format(espValue)
    #
    #             print "{:<10} {} {} {}".format(address, header, operand, espValue)
    #             display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, espValue))
    #
    #             totalCallCnt += 1

                raise Exception("Call instr at the end of a list")
            elif operand == "retl":

                remainder = remainder.split()
                if len(remainder) == 1:
                    espValue = '%x' % (int(remainder[0], 16) + 4)  # hex(int(remainder[0], 16) + 4)[2:-1]

                else:
                    espValue = '%x' % (int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)  # hex(int(remainder[0][2:], 16) + int(remainder[1], 16) + 4)[2:-1]


                if debug: print "{:<10} {} {} {}".format(address, header, operand, espValue)
                display.write("<li class='lastChild'>{:<10} {} {} {}</li>".format(address, header, operand, espValue))


                # print "totalRetCnt {}".format(espValue)


                # functionStack.pop()
            else:
                if debug: print "{:<10} {} {} {}".format(address, header, operand, remainder)

                display.write("<li>{:<10} {} {} {}</li>".format(address, header, operand, remainder))


        display.write("</ul></li>")




    # Run
    if visualize:


        display = open("output.html", "w")
        display.write('<script type="text/javascript" src="htmlextra/CollapsibleLists.js">'
                      + '</script><script type="text/javascript" src="htmlextra/runOnLoad.js">'
                      + '</script><link rel="stylesheet" type="text/css" href="htmlextra/style2.css" />')
        display.write('<ul class="collapsibleList"><li>Instructions<ul>')
        processList(currentInstructionList)

        display.write("</ul>")
        display.write('<script>CollapsibleLists.apply();</script>')




    logger.info("totalCallCnt {} totalRetCnt {} left {}".format(totalCallCnt, totalRetCnt, len(functionStack)))

    sortCallCnt = []
    for key in functionInfo.keys():
        x = functionInfo[key]
        sortCallCnt.append({"target":key,
                            "callCount":x["callCount"],
                            "confidence":1 - (float(sum(x["unresolvedRet"])) / x["callCount"]),
                            "mean":np.mean(x["instructionCount"]),
                            "median":np.median(x["instructionCount"]),
                            "totalInstr":sum(x["instructionCount"]),
                            "min":min(x["instructionCount"]), "max":max(x["instructionCount"])
                            })

    sortCallCnt.sort(key=lambda x : (x["totalInstr"], x["callCount"], x["target"]), reverse=True)


    if not chain:
        simplified_fmt = "{target} {callCount} {confidence} {min} {max} {mean} {median} {totalInstr}"
        if simplified:
            print simplified_fmt

        for ele in sortCallCnt[:]:
            # print ele

            if not simplified:
                if ele["callCount"] > 1:
                    print "{target} called {callCount}x. Confidence [{confidence}] Mean instr {mean}. Median {median}. Total instr exec {totalInstr}".format(**ele)
                else:
                    print "{target} called {callCount}x. Confidence [{confidence}] Instr exec {totalInstr}".format(**ele)
            else:
                print simplified_fmt.format(**ele)


    def getFunctionNameCmd(targetAddress, procFile, debug=False):
        """Print command to execute in console to fetch function name.

        Input:
        targetAddress - address in the form of a hexadecimal string appended with 0x
        procFile - output of /proc/pid/maps
        """
        try:
            targetAddress = int(targetAddress[2:], 16)
        except ValueError:
            print "Dynamic jump detected {}".format(targetAddress)
            return

        for line in open(procFile):
            l2 = line.split()
            src, dst = l2[0].split("-")
            src = int(src, 16)
            dst = int(dst, 16)


            if src <= targetAddress and targetAddress <= dst:
                if debug: print line
                offset = '%x' % (targetAddress - src)  # hex(targetAddress - src)[2:-1]
                location = line.split()[-1]

                if not location == "0":
                    print "objdump -d {} | grep {}  #0x{:x}".format(location, offset, targetAddress)
                else:
                    print "#Anon region for 0x{:x}".format(targetAddress)
                return
        print "#Not Found 0x{:x}".format(targetAddress)

    def getFunctionNameCmd2(targetAddress, procFile, debug=False):
        """Print command to execute in console to fetch function name.

        Input:
        targetAddress - address in the form of a hexadecimal string appended with 0x
        procFile - output of gentrace
        """
        try:
            targetAddress = int(targetAddress[2:], 16)
        except ValueError:
            return "Dynamic jump detected {}".format(targetAddress)

        for line in open(procFile):
            if not line.startswith("This is modload():"): continue
            l2 = line.split()
            src, dst = l2[-2:]
            src = int(src, 16)
            dst = int(dst, 16)

            if src <= targetAddress and targetAddress <= dst:
                if debug: print line
                offset = '%x' % (targetAddress - src)  # hex(targetAddress - src)[2:-1]
                location = l2[3]

                if not location == "0":
                    # print "objdump -d {} | grep 'call   {}' -m 1 #0x{:x}".format(location, offset, targetAddress)
                    return "{} {} 0x{:x}".format(location, offset, targetAddress)
                else:
                    return "#Anon region for 0x{:x}".format(targetAddress)

        return "#Not Found 0x{:x}".format(targetAddress)


    functionFetchInpt = []
    for ele in sortCallCnt[:]:
        functionFetchInpt.append(getFunctionNameCmd2(ele["target"], testInput[1]))

    if logger.getEffectiveLevel() <= logging.DEBUG:
        for line in functionFetchInpt:
            logger.debug(line)

    return (sortCallCnt, functionFetchInpt)


def genAIESP(trace):
    logger = logging.getLogger(__name__)

    handler, name = mkstemp()
    logger.info("Temp aiesp file created at " + name)

    cmd = "bin/fetchAIESP {0}".format(trace)
    logger.debug("Executing command: " + cmd)

    with os.popen(cmd) as result, open(name, "w") as f:
        f.writelines(result)

    logger.info("aiesp generated")
    return name

def getFunctionName(functionFetchInpt):
    logger = logging.getLogger(__name__)

    ret = []
    for line in functionFetchInpt:
        if line[:1] == "#" or not len(line):
            ret.append(line)
            logger.debug("skipping: " + line)
            continue

        try:
            # try 1
            found = False
            location, offset, target = line.split()

            cmd = "objdump -d {0} | grep 'call   {1}' -m 1".format(location, offset)
            logger.debug("Executing command: " + cmd)
            with os.popen(cmd) as result:
                rst = result.read().strip()

                if rst == "":
                    # print location, offset, target
                    pass
                else:
                    name = rst.split()[-1]
                    ret.append(name)
                    logger.debug("Function name is " + name)
                    # print "f"
                    found = True
                    pass

            if found: continue

            # try 2
            cmd = "objdump -d {0} | grep 'call   {1}' -m 1".format(location, target[2:])
            logger.debug("Executing command: " + cmd)
            with os.popen(cmd) as result:
                rst = result.read().strip()

                if rst == "":
                    # print location, offset, target
                    pass
                else:
                    name = rst.split()[-1]
                    ret.append(name)
                    logger.debug("Function name is " + name)
                    # print "f"
                    found = True

            if found: continue

            # try 3
            cmd = "objdump -d {0} | grep ^{1:0>8} -m 1".format(location, offset)
            logger.debug("Executing command: " + cmd)
            with os.popen(cmd) as result:
                rst = result.read().strip()

                if rst == "":
                    # print location, offset, target
                    pass
                else:
                    name = rst.split()[-1]
                    ret.append(name)
                    logger.debug("Function name is " + name)
                    # print "f"
                    found = True

            if found: continue



            ret.append("#Unknown {0} {1} {2}".format(location, offset, target))
            logger.debug("Function unknown")
        except:
            import sys
            print "Unexpected error:", sys.exc_info()[0]
            print line
            raise
    return ret

def main():
    import argparse, os
    parser = argparse.ArgumentParser(description="Analyze function in trace file.")
    parser.add_argument("trace", help="Path to trace file (*.bpt).")
    parser.add_argument("modload", help="Output of gentrace.")
    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
    if not os.path.exists(args.trace):
        parser.error("trace file do not exist");
    if not os.path.exists(args.modload):
        parser.error("modload file do not exist");

    if args.verbose == 1: logging.basicConfig(level=logging.INFO)
    if args.verbose > 1: logging.basicConfig(level=logging.DEBUG)


    name = genAIESP(args.trace)
    sortCallCnt, functionFetchInpt = runAnalysis(name, args.modload, chain=True)
    functNames = getFunctionName(functionFetchInpt)

    os.unlink(name)


if __name__ == "__main__":
    main()
