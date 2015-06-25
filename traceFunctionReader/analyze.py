import re
import numpy as np

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


import sys
sys.setrecursionlimit(10000000)
inpt = []


testInput = [("scwuftpd-skiplib.aiesp", "proc-map-wu-ftpd.txt"),
             ("3150-out-noskip.aiesp", "bof1-maps", 90897, 91589),  # 0x804856b, 0x8048588
             ("3577-bof2-noskip.aiesp", "bof2-maps"),
             ("3564-bof2-skip.aiesp", "bof2-maps"),
             ("5802-readme.aiesp", "")  # [91219:91912]
             ]
testChoice = 0
testInput = testInput[testChoice]

visualize = 0



# # Init List

functionStack = []
totalCallCnt = totalRetCnt = 0
currentInstructionList = []  # Current function
currentInstrCount = 0
currentFunctionCallCnt = 0
currentFunctionContainUnresolvedRet = 0


functionInfo = {}
totalCallCnt = totalRetCnt = 0
inputFile = testInput[0]



lmin = lmax = -1

if len(testInput) > 2:
    lmin = testInput[2] - 1
    if len(testInput) > 3:
        lmax = testInput[3] - 1

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



# Processing


def butlast(xs):
    xs = iter(xs)
    prev = xs.next()
    for x in xs:
        yield prev
        prev = x


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

                if debug: print "{:<10} {} {} {}".format(address, header, operand, espValue)
                display.write("<li>{:<10} {} {} {}<ul>".format(address, header, operand, espValue))
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



print "\n\n"
print "totalCallCnt {} totalRetCnt {} left {}".format(totalCallCnt, totalRetCnt, len(functionStack))

sortCallCnt = []
for key in functionInfo.keys():
    x = functionInfo[key]
    sortCallCnt.append({"target":key,
                        "callCount":x["callCount"],
                        "confidence":1 - (float(sum(x["unresolvedRet"])) / x["callCount"]),
                        "mean":np.mean(x["instructionCount"]),
                        "median":np.median(x["instructionCount"]),
                        "totalInstr":sum(x["instructionCount"])
                        })

sortCallCnt.sort(key=lambda x : (x["callCount"], x["target"]), reverse=True)

for ele in sortCallCnt[:]:
    # print ele
    if ele["callCount"] > 1:
        print "{target} called {callCount}x. Confidence [{confidence}] Mean instr {mean}. Median {median}. Total instr exec {totalInstr}".format(**ele)
    else:
        print "{target} called {callCount}x. Confidence [{confidence}] Instr exec {totalInstr}".format(**ele)


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

            print "objdump -d {} | grep {}".format(location, offset)
            return
    print "Not Found {}".format(targetAddress)



print "\n\nRun this on the server to get the list of function names.\n\n"


for ele in sortCallCnt[:]:
    getFunctionNameCmd(ele["target"], testInput[1])

